package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestResearchAuthorizationDecisionAblation evaluates only the decision point,
// never the complete training pipeline. B1, B2 and P share real mTLS-identity
// parsing, JWT verification, certificate/token binding, and RPC role rules.
// B1 removes active registration, B2 adds it, and P adds application freshness
// and replay cache checks in this test-only handler. The production coordinator
// remains strict in all builds, including when this test executes.
func TestResearchAuthorizationDecisionAblation(t *testing.T) {
	for _, profile := range []string{"B1_token_role", "B2_enrollment", "P_stateful"} {
		t.Run(profile, func(t *testing.T) {
			registry := ztsecurity.NewRegistrationStore()
			authorizer, key := lifecycleAuthorizer(t, registry)
			rule := authorizer.Rules[ztsecurity.MethodSubmitLocalUpdate]
			rule.RequireRegistration = profile != "B1_token_role"
			authorizer.Rules[ztsecurity.MethodSubmitLocalUpdate] = rule
			service, err := NewService(registry, Config{})
			if err != nil {
				t.Fatal(err)
			}
			good, goodCtx := lifecycleAuthorizedPeer(t, key, "good-node", "edge-worker")
			absent, absentCtx := lifecycleAuthorizedPeer(t, key, "absent-node", "edge-worker")
			revoked, revokedCtx := lifecycleAuthorizedPeer(t, key, "revoked-node", "edge-worker")
			observer, observerCtx := lifecycleAuthorizedPeer(t, key, "observer-node", "observer")
			for _, identity := range []ztsecurity.PeerIdentity{good, revoked, observer} {
				if _, err := registry.Register(identity, "registration-"+identity.NodeID, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := registry.Revoke(revoked.NodeID, "test-only compromise"); err != nil {
				t.Fatal(err)
			}
			replayNonce := []byte("ablation-replay-nonce-01")
			if profile == "P_stateful" {
				service.roundMu.Lock()
				service.acceptNonceLocked(good.NodeID, replayNonce, time.Now().UTC())
				service.roundMu.Unlock()
			}
			type scenario struct {
				name     string
				identity ztsecurity.PeerIdentity
				ctx      context.Context
				metadata *flv1.SecurityMetadata
				attack   bool
			}
			testCases := []scenario{
				{name: "legitimate", identity: good, ctx: goodCtx, metadata: lifecycleSecurityMetadata([]byte("ablation-valid-nonce-01"))},
				{name: "unenrolled", identity: absent, ctx: absentCtx, metadata: lifecycleSecurityMetadata([]byte("ablation-absent-nonce01")), attack: true},
				{name: "revoked", identity: revoked, ctx: revokedCtx, metadata: lifecycleSecurityMetadata([]byte("ablation-revoke-nonce01")), attack: true},
				{name: "role_denied", identity: observer, ctx: observerCtx, metadata: lifecycleSecurityMetadata([]byte("ablation-observe-nonce1")), attack: true},
				{name: "replay", identity: good, ctx: goodCtx, metadata: lifecycleSecurityMetadata(replayNonce), attack: true},
				{name: "stale_timestamp", identity: good, ctx: goodCtx, metadata: &flv1.SecurityMetadata{IssuedAtUnix: time.Now().UTC().Add(-5 * time.Minute).Unix(), Nonce: []byte("ablation-stale-nonce01")}, attack: true},
			}
			for _, scenario := range testCases {
				request := &flv1.SubmitLocalUpdateRequest{
					NodeId:         scenario.identity.NodeID,
					RegistrationId: "registration-" + scenario.identity.NodeID,
					Security:       scenario.metadata,
				}
				handler := func(_ context.Context, input any) (any, error) {
					if profile == "P_stateful" {
						req := input.(*flv1.SubmitLocalUpdateRequest)
						now := time.Now().UTC()
						if err := validateSecurityMetadata(req.GetSecurity(), now); err != nil {
							return nil, status.Error(codes.InvalidArgument, err.Error())
						}
						service.roundMu.Lock()
						defer service.roundMu.Unlock()
						if !service.acceptNonceLocked(req.GetNodeId(), req.GetSecurity().GetNonce(), now) {
							return nil, status.Error(codes.AlreadyExists, "replayed nonce")
						}
					}
					return &flv1.SubmitLocalUpdateResponse{Accepted: true}, nil
				}
				response, decisionErr := invokeLifecycleRPC(authorizer, scenario.ctx,
					ztsecurity.MethodSubmitLocalUpdate, request, handler)
				accepted := decisionErr == nil && response.(*flv1.SubmitLocalUpdateResponse).GetAccepted()
				expected := scenario.name == "legitimate"
				if profile == "B1_token_role" {
					expected = scenario.name != "role_denied"
				} else if profile == "B2_enrollment" {
					expected = scenario.name == "legitimate" || scenario.name == "replay" || scenario.name == "stale_timestamp"
				}
				record := map[string]any{
					"profile": profile, "scenario": scenario.name,
					"attack": scenario.attack, "accepted": accepted,
					"grpc_code":     status.Code(decisionErr).String(),
					"decision_only": true, "model_mutation_executed": false,
				}
				encoded, _ := json.Marshal(record)
				fmt.Printf("ZTFL_AUTHZ_ABLATION %s\n", encoded)
				if accepted != expected {
					t.Errorf("%s/%s accepted=%t, want %t; error=%v", profile, scenario.name, accepted, expected, decisionErr)
				}
			}
		})
	}
}
