package coordinator

import (
	"context"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
)

// BenchmarkResearchRPCPolicyDecision measures IN-PROCESS interceptor checks,
// not transport, persisted state transitions, throughput or model convergence.
// Token, certificate, method, and workload are held fixed; the only ablation
// is whether the authorization interceptor checks active enrollment.
func BenchmarkResearchRPCPolicyDecision(b *testing.B) {
	configs := []struct {
		name               string
		requireEnrollment bool
	}{
		{name: "token_role_only", requireEnrollment: false},
		{name: "token_role_plus_enrollment", requireEnrollment: true},
	}
	for _, testCase := range configs {
		b.Run(testCase.name, func(b *testing.B) {
			registry := ztsecurity.NewRegistrationStore()
			authorizer, privateKey := lifecycleAuthorizer(b, registry)
			identity, ctx := lifecycleAuthorizedPeer(b, privateKey, "research-benchmark-worker", "edge-worker")
			if _, err := registry.Register(identity, "research-benchmark-registration", time.Hour); err != nil {
				b.Fatal(err)
			}
			authorizer.Rules[ztsecurity.MethodGetGlobalModel] = ztsecurity.MethodRule{
				Roles: []string{"edge-worker"},
				RequireRegistration: testCase.requireEnrollment,
			}
			req := &flv1.GetGlobalModelRequest{
				NodeId: identity.NodeID,
				RegistrationId: "research-benchmark-registration",
			}
			handler := func(context.Context, any) (any, error) { return nil, nil }
			if _, err := invokeLifecycleRPC(authorizer, ctx, ztsecurity.MethodGetGlobalModel, req, handler); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := invokeLifecycleRPC(authorizer, ctx, ztsecurity.MethodGetGlobalModel, req, handler); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
