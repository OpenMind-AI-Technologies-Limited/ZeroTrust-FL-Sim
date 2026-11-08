package coordinator

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A rejected stale-round request must not burn a nonce before the update
// reaches the model-state transition. The same security metadata may be
// retried after correcting a non-security precondition; a committed request
// must still be rejected on replay.
func TestRejectedStaleUpdateDoesNotConsumeNonce(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	service, err := NewService(registry, Config{})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, privateKey := lifecycleAuthorizer(t, registry)
	identity, ctx := lifecycleAuthorizedPeer(t, privateKey, "replay-worker", "edge-worker")
	entry, err := registry.Register(identity, "research-registration", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeNPYFloat32([]float32{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	req := &flv1.SubmitLocalUpdateRequest{
		NodeId: identity.NodeID, RegistrationId: entry.RegistrationID,
		RoundId: 0, BaseModelVersion: "stale-version",
		WeightsPayload: payload, WeightsFormat: networkWeightsFormat,
		UpdateSha256: digest[:],
		Metrics: &flv1.LocalUpdateMetrics{SampleCount: 1},
		Security: lifecycleSecurityMetadata([]byte("research-replay-0001")),
	}
	invoke := func() (any, error) {
		return invokeLifecycleRPC(authorizer, ctx, ztsecurity.MethodSubmitLocalUpdate,
			req, func(handlerCtx context.Context, input any) (any, error) {
				return service.SubmitLocalUpdate(handlerCtx, input.(*flv1.SubmitLocalUpdateRequest))
			})
	}
	if _, err := invoke(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale version: got %v; want FailedPrecondition", err)
	}
	if len(service.nonces) != 0 || len(service.rates) != 0 || len(service.pending) != 0 {
		t.Fatal("rejected stale update mutated security or pending state")
	}
	req.BaseModelVersion = "bootstrap"
	res, err := invoke()
	if err != nil {
		t.Fatalf("corrected update was rejected: %v", err)
	}
	if !res.(*flv1.SubmitLocalUpdateResponse).GetAccepted() {
		t.Fatal("corrected update was not accepted")
	}
	if _, err := invoke(); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("replayed committed nonce: got %v; want AlreadyExists", err)
	}
}

// Failed revocation must not burn the administrator's nonce. Successful
// revocation burns it, and replay is denied even if the target is still revoked.
func TestFailedRevocationDoesNotConsumeNonce(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	service, err := NewService(registry, Config{})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, privateKey := lifecycleAuthorizer(t, registry)
	admin, ctx := lifecycleAuthorizedPeer(t, privateKey, "research-admin", "admin")
	entry, err := registry.Register(admin, "admin-registration", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := &flv1.RevokeRegistrationRequest{
		NodeId: admin.NodeID, RegistrationId: entry.RegistrationID,
		TargetNodeId: "not-yet-enrolled", Reason: "suspected credential theft",
		Security: lifecycleSecurityMetadata([]byte("research-revoke-0001")),
	}
	invoke := func() (any, error) {
		return invokeLifecycleRPC(authorizer, ctx, ztsecurity.MethodRevokeRegistration,
			req, func(handlerCtx context.Context, input any) (any, error) {
				return service.RevokeRegistration(handlerCtx, input.(*flv1.RevokeRegistrationRequest))
			})
	}
	if _, err := invoke(); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown revocation target: got %v; want NotFound", err)
	}
	if len(service.nonces) != 0 {
		t.Fatal("failed revocation consumed the nonce")
	}
	worker, _ := lifecycleAuthorizedPeer(t, privateKey, req.TargetNodeId, "edge-worker")
	if _, err := registry.Register(worker, "worker-registration", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(); err != nil {
		t.Fatalf("valid revocation with the same nonce was rejected: %v", err)
	}
	if registry.IsRegistered(worker) {
		t.Fatal("revoked worker remained authorized")
	}
	if _, err := invoke(); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("replayed revocation nonce: got %v; want AlreadyExists", err)
	}
}
