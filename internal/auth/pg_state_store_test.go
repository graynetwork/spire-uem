package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
)

// fakeStateRepo is an in-memory stand-in for the Postgres-backed OIDC state repo, modelling
// the single-use + TTL contract so PostgresStateStore can be tested without a database.
type fakeStateRepo struct {
	mu     sync.Mutex
	states map[string]stored
	putErr error
}

type stored struct {
	s         db.OIDCLoginState
	expiresAt time.Time
}

func newFakeStateRepo() *fakeStateRepo { return &fakeStateRepo{states: map[string]stored{}} }

func (f *fakeStateRepo) PutOIDCLoginState(_ context.Context, state string, s db.OIDCLoginState, ttl time.Duration) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}
	f.states[state] = stored{s: s, expiresAt: now.Add(ttl)}
	return nil
}

func (f *fakeStateRepo) PopOIDCLoginState(_ context.Context, state string) (db.OIDCLoginState, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.states[state]
	if !ok {
		return db.OIDCLoginState{}, false, nil
	}
	delete(f.states, state) // single use: consumed on first pop
	if time.Now().After(v.expiresAt) {
		return db.OIDCLoginState{}, false, nil
	}
	return v.s, true, nil
}

func TestPostgresStateStore_RoundTrip(t *testing.T) {
	store := NewPostgresStateStore(newFakeStateRepo())
	ctx := context.Background()

	in := AuthState{
		CodeVerifier: "verifier-xyz",
		Nonce:        "nonce-123",
		RedirectURI:  "https://spire.example/admin/dashboard",
		CreatedAt:    time.Now(),
	}
	if err := store.Put(ctx, "state-A", in, 5*time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, found, err := store.Pop(ctx, "state-A")
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if !found {
		t.Fatal("expected state to be found")
	}
	if got.CodeVerifier != in.CodeVerifier || got.Nonce != in.Nonce || got.RedirectURI != in.RedirectURI {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, in)
	}
}

func TestPostgresStateStore_SingleUse(t *testing.T) {
	store := NewPostgresStateStore(newFakeStateRepo())
	ctx := context.Background()
	_ = store.Put(ctx, "state-B", AuthState{Nonce: "n", CreatedAt: time.Now()}, time.Minute)

	if _, found, _ := store.Pop(ctx, "state-B"); !found {
		t.Fatal("first pop should find the state")
	}
	// A replayed callback with the same state must fail (single use / CSRF defence).
	if _, found, _ := store.Pop(ctx, "state-B"); found {
		t.Fatal("second pop of the same state must NOT find it (single-use violated)")
	}
}

func TestPostgresStateStore_Expired(t *testing.T) {
	store := NewPostgresStateStore(newFakeStateRepo())
	ctx := context.Background()
	// Negative TTL => already expired.
	_ = store.Put(ctx, "state-C", AuthState{Nonce: "n", CreatedAt: time.Now()}, -time.Second)
	if _, found, _ := store.Pop(ctx, "state-C"); found {
		t.Fatal("expired state must not be returned")
	}
}

func TestPostgresStateStore_UnknownState(t *testing.T) {
	store := NewPostgresStateStore(newFakeStateRepo())
	if _, found, err := store.Pop(context.Background(), "never-put"); err != nil || found {
		t.Fatalf("unknown state: found=%v err=%v, want found=false err=nil", found, err)
	}
}

func TestPostgresStateStore_PutErrorPropagates(t *testing.T) {
	repo := newFakeStateRepo()
	repo.putErr = errors.New("db down")
	store := NewPostgresStateStore(repo)
	if err := store.Put(context.Background(), "s", AuthState{CreatedAt: time.Now()}, time.Minute); err == nil {
		t.Fatal("expected Put error to propagate")
	}
}

// The default (memory) store must also honour single-use so single-instance deployments are
// not weaker than clustered ones.
func TestMemoryStateStore_SingleUse(t *testing.T) {
	store := newMemoryStateStore()
	ctx := context.Background()
	_ = store.Put(ctx, "m1", AuthState{Nonce: "n", CreatedAt: time.Now()}, time.Minute)
	if _, found, _ := store.Pop(ctx, "m1"); !found {
		t.Fatal("first pop should find")
	}
	if _, found, _ := store.Pop(ctx, "m1"); found {
		t.Fatal("memory store must be single-use")
	}
}
