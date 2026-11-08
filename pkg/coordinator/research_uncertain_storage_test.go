package coordinator

import (
	"context"
	"errors"
	"testing"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type researchPermanentlyFailingStore struct{}

func (researchPermanentlyFailingStore) Load(context.Context) (StateSnapshot, error) {
	return StateSnapshot{}, ErrStateNotFound
}

func (researchPermanentlyFailingStore) Commit(context.Context, StateSnapshot) error {
	return errors.New("injected persistent I/O outage")
}

// A failed state commit followed by a failed durable rollback means the disk
// may contain an acknowledged or unacknowledged transition. An in-memory
// restore is insufficient to safely continue serving authorization requests.
func TestUncertainPersistentRollbackFencesEveryCoordinatorRPC(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	service, err := NewService(registry, Config{})
	if err != nil {
		t.Fatal(err)
	}
	durable := newRollbackTestDurableService(t, service, researchPermanentlyFailingStore{})
	before := durable.captureSnapshot()
	if err := durable.commitOrRollbackTransition(context.Background(), before, before, "fault-injected", nil); err == nil {
		t.Fatal("persistently failing state store returned success")
	}
	if !durable.fenced {
		t.Fatal("coordinator did not enter fail-stop fence on uncertain rollback")
	}
	// Check all six entry points; none may bypass the fence to consult stale
	// or uncertain credential and model state.
	checks := []struct {
		name string
		run  func() error
	}{
		{"register", func() error {
			_, err := durable.RegisterNode(context.Background(), &flv1.RegisterNodeRequest{})
			return err
		}},
		{"heartbeat", func() error {
			_, err := durable.Heartbeat(context.Background(), &flv1.HeartbeatRequest{})
			return err
		}},
		{"model-read", func() error {
			_, err := durable.GetGlobalModel(context.Background(), &flv1.GetGlobalModelRequest{})
			return err
		}},
		{"model-update", func() error {
			_, err := durable.SubmitLocalUpdate(context.Background(), &flv1.SubmitLocalUpdateRequest{})
			return err
		}},
		{"rotation", func() error {
			_, err := durable.RotateRegistration(context.Background(), &flv1.RotateRegistrationRequest{})
			return err
		}},
		{"revocation", func() error {
			_, err := durable.RevokeRegistration(context.Background(), &flv1.RevokeRegistrationRequest{})
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if got := status.Code(check.run()); got != codes.Unavailable {
				t.Fatalf("RPC returned %v, want Unavailable while fenced", got)
			}
		})
	}
}

// A recoverable storage fault must roll back in memory and on disk without
// fencing the system permanently. The failed operation is not acknowledged.
func TestRecoverableRollbackDoesNotFenceCoordinator(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	service, err := NewService(registry, Config{})
	if err != nil {
		t.Fatal(err)
	}
	durable := newRollbackTestDurableService(t, service, &failOnceStateStore{})
	before := durable.captureSnapshot()
	if err := durable.commitOrRollbackTransition(context.Background(), before, before, "fault-injected", nil); err == nil {
		t.Fatal("injected first commit did not fail")
	}
	if durable.fenced {
		t.Fatal("coordinator fenced despite successful durable rollback")
	}
}
