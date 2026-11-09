package tests

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/coordinator"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// End-to-end security experiment over TCP, mTLS 1.3, JWT and gRPC. This does
// not measure device-scale FL training, full SOTA protocols or network jitter.
func researchTLSRoundFixture(t *testing.T) *securityHarness {
	t.Helper()
	const sn = "fl-research.local"
	const issuer = "fl-research-issuer"
	const audience = "fl-research-audience"
	trust := ztsecurity.DefaultTrustDomain
	nodes := []ztsecurity.DevelopmentClient{{NodeID: "train-a", Role: "edge-worker"}, {NodeID: "train-b", Role: "edge-worker"}, {NodeID: "train-c", Role: "edge-worker"}, {NodeID: "train-d", Role: "edge-worker"}, {NodeID: "train-admin", Role: "admin"}}
	a, e := ztsecurity.GenerateDevelopmentPKI(ztsecurity.DevelopmentPKIConfig{OutputDir: filepath.Join(t.TempDir(), "pki"), TrustDomain: trust, ServerName: sn, Issuer: issuer, Audience: audience, Clients: nodes})
	if e != nil {
		t.Fatal(e)
	}
	creds, e := ztsecurity.ServerTransportCredentials(ztsecurity.ServerTLSOptions{CertificateFile: a.ServerCertificateFile, PrivateKeyFile: a.ServerPrivateKeyFile, ClientCAFile: a.CACertificateFile, TrustDomain: trust, AllowedClientRoles: []string{"edge-worker", "admin"}})
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := ztsecurity.NewTokenVerifierFromPEMFile(a.JWTSigningPublicKeyFile, issuer, audience, 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	registry := ztsecurity.NewRegistrationStore()
	authorizer, e := ztsecurity.NewAuthorizer(trust, verifier, registry)
	if e != nil {
		t.Fatal(e)
	}
	store, e := coordinator.NewFileStateStore(filepath.Join(t.TempDir(), "durable-state.json"))
	if e != nil {
		t.Fatal(e)
	}
	durable, e := coordinator.NewDurableService(registry, coordinator.Config{MinUpdates: 3, LeaseTTL: 10 * time.Minute, MaxUpdatesPerMinute: 500, AggregationMethod: "weighted_mean"}, store)
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := coordinator.NewEnvelopeService(durable, coordinator.DefaultModelID)
	if e != nil {
		t.Fatal(e)
	}
	lis, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	server := grpc.NewServer(grpc.Creds(creds), grpc.ChainUnaryInterceptor(authorizer.UnaryServerInterceptor()))
	flv1.RegisterCoordinatorServiceServer(server, envelope)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.Stop(); _ = lis.Close() })
	return &securityHarness{address: lis.Addr().String(), serverName: sn, trustDomain: trust, issuer: issuer, audience: audience, artifacts: a}
}

func researchVector(t *testing.T, v []float32) []byte {
	t.Helper()
	h := fmt.Sprintf("{'descr': '<f4', 'fortran_order': False, 'shape': (%d,), }", len(v))
	h += fmt.Sprintf("%*s", (16-(10+len(h)+1)%16)%16, "") + "\n"
	b := make([]byte, 10+len(h)+len(v)*4)
	copy(b[:6], []byte("\x93NUMPY"))
	b[6] = 1
	binary.LittleEndian.PutUint16(b[8:10], uint16(len(h)))
	copy(b[10:], []byte(h))
	for i, x := range v {
		binary.LittleEndian.PutUint32(b[10+len(h)+4*i:], math.Float32bits(x))
	}
	return b
}

func TestResearchE2ETLSRoundRevocationReplay(t *testing.T) {
	h := researchTLSRoundFixture(t)
	clients := map[string]flv1.CoordinatorServiceClient{}
	ids := map[string]string{}
	for _, id := range []string{"train-a", "train-b", "train-c", "train-d", "train-admin"} {
		clients[id] = h.newClient(t, id, "").Coordinator
	}
	call := func(f func(context.Context) error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := f(ctx); e != nil {
			t.Fatal(e)
		}
	}
	register := func(id string) {
		call(func(ctx context.Context) error {
			r, e := clients[id].RegisterNode(ctx, &flv1.RegisterNodeRequest{NodeId: id, CertificateCommonName: id, Hardware: &flv1.HardwareProfile{Architecture: "amd64"}, Security: mutationSecurityMetadata(t)})
			if e == nil {
				ids[id] = r.GetRegistrationId()
			}
			return e
		})
	}
	for _, id := range []string{"train-a", "train-b", "train-c", "train-admin"} {
		register(id)
	}
	schema, _ := hex.DecodeString("cff606025d8af83f907bc6d4c6b82000e3c22b67d16bf8a3e9999f816c1c5e64")
	getModel := func() *flv1.GlobalModel {
		var m *flv1.GlobalModel
		call(func(ctx context.Context) error {
			var e error
			m, e = clients["train-a"].GetGlobalModel(ctx, &flv1.GetGlobalModelRequest{NodeId: "train-a", RegistrationId: ids["train-a"]})
			return e
		})
		return m
	}
	model := getModel()
	if model.GetRoundId() != 0 {
		t.Fatal("initial round is not zero")
	}
	var firstNonce []byte
	latencies := []float64{}
	submit := func(node string, nonce []byte, want codes.Code) {
		t.Helper()
		m := getModel()
		payload := researchVector(t, []float32{0.1, 0.2, 0.3})
		sum := sha256.Sum256(payload)
		req := &flv1.SubmitLocalUpdateRequest{NodeId: node, RegistrationId: ids[node], RoundId: m.GetRoundId(), BaseModelVersion: m.GetModelVersion(), WeightsPayload: payload, WeightsFormat: "application/x-npy-f32", UpdateSha256: sum[:], Metrics: &flv1.LocalUpdateMetrics{DynamicEpochs: 1, SampleCount: 10}, Security: &flv1.SecurityMetadata{IssuedAtUnix: time.Now().UTC().Unix(), Nonce: nonce}, ProtocolVersion: coordinator.ModelProtocolVersion, ModelId: coordinator.DefaultModelID, SchemaSha256: schema, TensorManifest: []*flv1.TensorManifestEntry{{Name: "flat_weights", Dtype: "float32", Dimensions: []uint64{3}, ElementCount: 3}}}
		started := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, e := clients[node].SubmitLocalUpdate(ctx, req)
		cancel()
		latencies = append(latencies, float64(time.Since(started).Microseconds())/1000)
		if status.Code(e) != want {
			t.Fatalf("%s: got %v, expected %v", node, e, want)
		}
	}
	firstNonce = mutationSecurityMetadata(t).Nonce
	submit("train-a", firstNonce, codes.OK)
	submit("train-b", mutationSecurityMetadata(t).Nonce, codes.OK)
	submit("train-c", mutationSecurityMetadata(t).Nonce, codes.OK)
	if got := getModel().GetRoundId(); got != 1 {
		t.Fatalf("expected first quorum round 1, got %d", got)
	}
	submit("train-a", firstNonce, codes.AlreadyExists)
	call(func(ctx context.Context) error {
		r, e := clients["train-admin"].RevokeRegistration(ctx, &flv1.RevokeRegistrationRequest{NodeId: "train-admin", RegistrationId: ids["train-admin"], TargetNodeId: "train-c", Reason: "controlled compromised client", Security: mutationSecurityMetadata(t)})
		if e != nil {
			return e
		}
		if !r.GetAccepted() {
			t.Fatal("revocation not acknowledged")
		}
		return nil
	})
	submit("train-c", mutationSecurityMetadata(t).Nonce, codes.PermissionDenied)
	submit("train-a", mutationSecurityMetadata(t).Nonce, codes.OK)
	submit("train-b", mutationSecurityMetadata(t).Nonce, codes.OK)
	if got := getModel().GetRoundId(); got != 1 {
		t.Fatal("quorum advanced with revoked worker absent")
	}
	register("train-d")
	submit("train-d", mutationSecurityMetadata(t).Nonce, codes.OK)
	if got := getModel().GetRoundId(); got != 2 {
		t.Fatalf("replacement did not restore progress, round=%d", got)
	}
	fmt.Printf("ZTFL_REAL_TLS_SECURITY {\"accepted_update_rounds\":2,\"revoked_update_denied\":true,\"replay_denied\":true,\"replaced_quorum\":true,\"tls_version\":\"1.3\",\"latencies_ms\":%v}\n", latencies)
}
