package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The available set shrinks after a worker is revoked. With a fixed quorum,
// progress depends on replacement capacity. This is an actual in-process Go
// coordinator-state experiment, not model-training accuracy measurement.
func TestResearchQuorumAvailabilityWithRevocation(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	service, err := NewService(registry, Config{MinUpdates: 3})
	if err != nil {
		t.Fatal(err)
	}
	auth, key := lifecycleAuthorizer(t, registry)
	identities := make(map[string]ztsecurity.PeerIdentity)
	contexts := make(map[string]context.Context)
	for _, node := range []string{"worker-a", "worker-b", "worker-c", "worker-d", "admin-a"} {
		role := "edge-worker"
		if node == "admin-a" {
			role = "admin"
		}
		identity, ctx := lifecycleAuthorizedPeer(t, key, node, role)
		identities[node] = identity
		contexts[node] = ctx
		if node != "worker-d" {
			if _, err := registry.Register(identity, "registration-"+node, time.Hour); err != nil {
				t.Fatal(err)
			}
		}
	}
	revoke := &flv1.RevokeRegistrationRequest{
		NodeId:         "admin-a",
		RegistrationId: "registration-admin-a",
		TargetNodeId:   "worker-c",
		Reason:         "worker credential was compromised",
		Security:       lifecycleSecurityMetadata([]byte("quorum-revocation-nonce")),
	}
	if _, err := invokeLifecycleRPC(auth, contexts["admin-a"], ztsecurity.MethodRevokeRegistration,
		revoke, func(ctx context.Context, input any) (any, error) {
			return service.RevokeRegistration(ctx, input.(*flv1.RevokeRegistrationRequest))
		}); err != nil {
		t.Fatal(err)
	}
	payload, err := encodeNPYFloat32([]float32{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	submit := func(node string, nonce string) error {
		request := &flv1.SubmitLocalUpdateRequest{
			NodeId:           node,
			RegistrationId:   "registration-" + node,
			RoundId:          0,
			BaseModelVersion: "bootstrap",
			WeightsPayload:   payload,
			WeightsFormat:    networkWeightsFormat,
			UpdateSha256:     digest[:],
			Metrics:          &flv1.LocalUpdateMetrics{DynamicEpochs: 1, SampleCount: 1},
			Security:         lifecycleSecurityMetadata([]byte(nonce)),
		}
		_, err := invokeLifecycleRPC(auth, contexts[node], ztsecurity.MethodSubmitLocalUpdate,
			request, func(ctx context.Context, input any) (any, error) {
				return service.SubmitLocalUpdate(ctx, input.(*flv1.SubmitLocalUpdateRequest))
			})
		return err
	}
	for _, node := range []string{"worker-a", "worker-b"} {
		if err := submit(node, "quorum-nonce-"+node); err != nil {
			t.Fatal(err)
		}
	}
	if got := service.currentModel().GetRoundId(); got != 0 {
		t.Fatalf("quorum should stall after two of three updates, got round %d", got)
	}
	if got := status.Code(submit("worker-c", "quorum-revoked-nonce")); got != codes.PermissionDenied {
		t.Fatalf("revoked worker request returned %v, want PermissionDenied", got)
	}
	if got := service.currentModel().GetRoundId(); got != 0 {
		t.Fatalf("revoked contribution advanced global model to round %d", got)
	}
	if _, err := registry.Register(identities["worker-d"], "registration-worker-d", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := submit("worker-d", "quorum-replacement-nonce"); err != nil {
		t.Fatal(err)
	}
	if got := service.currentModel().GetRoundId(); got != 1 {
		t.Fatalf("replacement worker did not complete quorum; round=%d", got)
	}
	record := map[string]any{
		"study": "control_plane_quorum_availability",
		"required_updates": 3,
		"initial_active_workers": 3,
		"revoked_before_submission": 1,
		"round_completed_before_replacement": false,
		"round_completed_after_replacement": true,
		"denied_revoked_worker": true,
		"network_and_training_evaluated": false,
	}
	encoded, _ := json.Marshal(record)
	fmt.Printf("ZTFL_ROUND_AVAILABILITY %s\n", encoded)
}
