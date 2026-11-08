package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// researchModelBaseline is a deliberately isolated, test-only coordinator
// adapter with the same one-client median aggregation and model-version
// transition as production. It removes exactly the enrollment check for B1
// or the nonce/durable checks for B2. It is NOT a production configuration,
// independently published competitor, or a network performance comparator.
type researchModelBaseline struct {
	service *Service
	enforceEnrollment bool
}

func (b *researchModelBaseline) SubmitLocalUpdate(ctx context.Context, req *flv1.SubmitLocalUpdateRequest) (*flv1.SubmitLocalUpdateResponse, error) {
	identity, ok := ztsecurity.AuthorizedPeerIdentity(ctx)
	if !ok || req == nil || req.GetNodeId() != identity.NodeID {
		return nil, status.Error(codes.PermissionDenied, "unbound request identity")
	}
	s := b.service
	s.roundMu.Lock()
	defer s.roundMu.Unlock()
	if b.enforceEnrollment {
		if _, err := s.registry.Validate(identity, req.GetRegistrationId()); err != nil {
			return nil, status.Error(codes.PermissionDenied, "inactive enrollment")
		}
	}
	if req.GetWeightsFormat() != networkWeightsFormat {
		return nil, status.Error(codes.InvalidArgument, "unexpected weights format")
	}
	digest := sha256.Sum256(req.GetWeightsPayload())
	if !bytes.Equal(digest[:], req.GetUpdateSha256()) {
		return nil, status.Error(codes.InvalidArgument, "payload digest mismatch")
	}
	if err := validateMetrics(req.GetMetrics()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	values, err := decodeNPYFloat32(req.GetWeightsPayload())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	model := s.currentModel()
	if req.GetRoundId() != model.GetRoundId() || req.GetBaseModelVersion() != model.GetModelVersion() {
		return nil, status.Error(codes.FailedPrecondition, "stale model state")
	}
	currentValues, err := currentModelVector(model, len(values))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// This experiment is restricted to quorum=1, median aggregation, with the
	// same elementwise update and model version computation as production.
	for index := range currentValues {
		currentValues[index] += values[index]
	}
	encoded, err := encodeNPYFloat32(currentValues)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	resultDigest := sha256.Sum256(encoded)
	nextRound := model.GetRoundId() + 1
	nextVersion := fmt.Sprintf("round-%d-%s", nextRound, hex.EncodeToString(resultDigest[:8]))
	s.modelMu.Lock()
	s.model = &flv1.GlobalModel{
		ModelVersion: nextVersion,
		RoundId: nextRound,
		WeightsPayload: encoded,
		WeightsFormat: networkWeightsFormat,
		Sha256: resultDigest[:],
		CreatedAtUnix: time.Now().UTC().Unix(),
	}
	s.modelMu.Unlock()
	return &flv1.SubmitLocalUpdateResponse{
		Accepted: true, UpdateId: "test-only-accepted", CurrentModelVersion: nextVersion,
	}, nil
}

// TestResearchModelMutationBaselineAblation tests actual model-round mutation
// (not only authorization-decision counts) under research-constructed B1/B2/P
// policies. Transport is represented by a synthetic verified TLS peer context
// and a genuine signed JWT validated by the same production interceptor.
// The experiment does not exercise wire latency or multi-worker aggregation.
func TestResearchModelMutationBaselineAblation(t *testing.T) {
	profiles := []string{"B1_token_role", "B2_enrollment", "P_durable_policy"}
	scenarios := []string{"legitimate", "unenrolled", "revoked", "observer_role", "cross_round_nonce_reuse"}
	for _, profile := range profiles {
		for _, scenario := range scenarios {
			t.Run(profile+"/"+scenario, func(t *testing.T) {
				registry := ztsecurity.NewRegistrationStore()
				auth, privateKey := lifecycleAuthorizer(t, registry)
				actorRole := "edge-worker"
				if scenario == "observer_role" {
					actorRole = "observer"
				}
				identity, ctx := lifecycleAuthorizedPeer(t, privateKey, "experiment-worker", actorRole)
				rule := auth.Rules[ztsecurity.MethodSubmitLocalUpdate]
				rule.RequireRegistration = profile != "B1_token_role"
				auth.Rules[ztsecurity.MethodSubmitLocalUpdate] = rule
				if scenario != "unenrolled" {
					if _, err := registry.Register(identity, "registration-experiment", time.Hour); err != nil {
						t.Fatal(err)
					}
				}
				cfg := Config{MinUpdates: 1, MaxUpdatesPerMinute: 1000}
				var inner *Service
				var invoke func(context.Context, *flv1.SubmitLocalUpdateRequest) (*flv1.SubmitLocalUpdateResponse, error)
				if profile == "P_durable_policy" {
					store, err := NewFileStateStore(fmt.Sprintf("%s/coordinator.json", t.TempDir()))
					if err != nil {
						t.Fatal(err)
					}
					durable, err := NewDurableService(registry, cfg, store)
					if err != nil {
						t.Fatal(err)
					}
					inner = durable.service
					invoke = durable.SubmitLocalUpdate
				} else {
					s, err := NewService(registry, cfg)
					if err != nil {
						t.Fatal(err)
					}
					inner = s
					baseline := &researchModelBaseline{service:s, enforceEnrollment:profile=="B2_enrollment"}
					invoke = baseline.SubmitLocalUpdate
				}
				if scenario == "revoked" {
					if _, err := registry.Revoke(identity.NodeID, "test-only revocation"); err != nil {
						t.Fatal(err)
					}
				}
				payload, err := encodeNPYFloat32([]float32{0.125, -0.25})
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(payload)
				nonce := []byte("cross-round-replay-nonce")
				apply := func(phase string) (bool, codes.Code) {
					current := inner.currentModel()
					request := &flv1.SubmitLocalUpdateRequest{
						NodeId: identity.NodeID,
						RegistrationId: "registration-experiment",
						RoundId: current.GetRoundId(),
						BaseModelVersion: current.GetModelVersion(),
						WeightsPayload: payload,
						WeightsFormat: networkWeightsFormat,
						UpdateSha256: digest[:],
						Metrics: &flv1.LocalUpdateMetrics{DynamicEpochs:1, SampleCount:1},
						Security: lifecycleSecurityMetadata(nonce),
					}
					resp, err := invokeLifecycleRPC(auth, ctx, ztsecurity.MethodSubmitLocalUpdate,
						request, func(handlerCtx context.Context, input any) (any, error) {
							return invoke(handlerCtx, input.(*flv1.SubmitLocalUpdateRequest))
						})
					accepted := err == nil && resp.(*flv1.SubmitLocalUpdateResponse).GetAccepted()
					event := map[string]any{
						"profile": profile, "scenario": scenario,
						"phase": phase, "accepted": accepted,
						"grpc_code": status.Code(err).String(),
						"round_after": inner.currentModel().GetRoundId(),
						"real_model_mutation": accepted,
						"test_constructed_baseline": profile != "P_durable_policy",
					}
					raw, _ := json.Marshal(event)
					fmt.Printf("ZTFL_MODEL_BASELINE %s\n", raw)
					return accepted, status.Code(err)
				}
				first, _ := apply("initial")
				expectedFirst := scenario == "legitimate" || scenario == "cross_round_nonce_reuse"
				if profile == "B1_token_role" && (scenario == "unenrolled" || scenario == "revoked") {
					expectedFirst = true
				}
				if first != expectedFirst {
					t.Fatalf("first model mutation accepted=%t, want %t", first, expectedFirst)
				}
				if scenario == "cross_round_nonce_reuse" {
					second, code := apply("repeated_nonce_new_round")
					want := profile != "P_durable_policy"
					if second != want {
						t.Fatalf("second model mutation accepted=%t, want %t; status=%v", second, want, code)
					}
					if profile == "P_durable_policy" && code != codes.AlreadyExists {
						t.Fatalf("replayed nonce returned %v, want AlreadyExists", code)
					}
				}
			})
		}
	}
}
