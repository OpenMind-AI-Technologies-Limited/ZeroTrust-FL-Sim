package coordinator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
)

// BenchmarkResearchAuthenticatedRoundTransition compares the SAME Go round
// transition and identity/token checks with/without file-durable commits.
// It is an in-process microbenchmark: no TCP/TLS handshake, gRPC serialization,
// real training, or network transfer is measured. Each operation is accepted;
// nonce inputs are deterministic, unique, BENCHMARK-ONLY values.
// Do not claim this measures end-to-end FL performance.
func BenchmarkResearchAuthenticatedRoundTransition(b *testing.B) {
	for _, durableState := range []bool{false, true} {
		name := "in_memory_model_transition"
		if durableState {
			name = "file_durable_model_transition"
		}
		b.Run(name, func(b *testing.B) {
			registry := ztsecurity.NewRegistrationStore()
			authorizer, privateKey := lifecycleAuthorizer(b, registry)
			identity, ctx := lifecycleAuthorizedPeer(b, privateKey, "benchmark-node", "edge-worker")
			config := Config{MinUpdates: 1, MaxUpdatesPerMinute: 1000000}
			var server flv1.CoordinatorServiceServer
			var inner *Service
			if durableState {
				store, err := NewFileStateStore(filepath.Join(b.TempDir(), "coordinator-state.json"))
				if err != nil {
					b.Fatal(err)
				}
				service, err := NewDurableService(registry, config, store)
				if err != nil {
					b.Fatal(err)
				}
				inner = service.service
				server = service
			} else {
				service, err := NewService(registry, config)
				if err != nil {
					b.Fatal(err)
				}
				inner = service
				server = service
			}
			register := &flv1.RegisterNodeRequest{
				NodeId:                identity.NodeID,
				CertificateCommonName: identity.CommonName,
				Hardware:              &flv1.HardwareProfile{Architecture: "research"},
				Security:              lifecycleSecurityMetadata([]byte("benchmark-enrollment-nonce")),
			}
			resp, err := invokeLifecycleRPC(authorizer, ctx, ztsecurity.MethodRegisterNode,
				register, func(handlerCtx context.Context, request any) (any, error) {
					return server.RegisterNode(handlerCtx, request.(*flv1.RegisterNodeRequest))
				})
			if err != nil {
				b.Fatal(err)
			}
			registrationID := resp.(*flv1.RegisterNodeResponse).GetRegistrationId()
			payload, err := encodeNPYFloat32([]float32{0.001, -0.002, 0.003, -0.004})
			if err != nil {
				b.Fatal(err)
			}
			digest := sha256.Sum256(payload)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				global := inner.currentModel()
				request := &flv1.SubmitLocalUpdateRequest{
					NodeId:           identity.NodeID,
					RegistrationId:   registrationID,
					RoundId:          global.GetRoundId(),
					BaseModelVersion: global.GetModelVersion(),
					WeightsPayload:   payload,
					WeightsFormat:    networkWeightsFormat,
					UpdateSha256:     digest[:],
					Metrics:          &flv1.LocalUpdateMetrics{DynamicEpochs: 1, SampleCount: 1},
					Security: lifecycleSecurityMetadata([]byte(
						fmt.Sprintf("benchmark-nonce-%016d", i))),
				}
				accepted, updateErr := invokeLifecycleRPC(authorizer, ctx,
					ztsecurity.MethodSubmitLocalUpdate,
					request, func(handlerCtx context.Context, input any) (any, error) {
						return server.SubmitLocalUpdate(handlerCtx, input.(*flv1.SubmitLocalUpdateRequest))
					})
				if updateErr != nil {
					b.Fatal(updateErr)
				}
				if !accepted.(*flv1.SubmitLocalUpdateResponse).GetAccepted() {
					b.Fatal("coordinator did not accept valid benchmark update")
				}
			}
			b.StopTimer()
			if got := inner.currentModel().GetRoundId(); got != uint64(b.N) {
				b.Fatalf("round after %d updates = %d", b.N, got)
			}
		})
	}
}
