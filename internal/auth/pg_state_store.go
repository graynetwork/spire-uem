package auth

import (
	"context"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
)

// oidcStateRepo is the subset of *db.Repository the Postgres state store needs. Declaring
// it as an interface keeps auth loosely coupled and makes the store unit-testable with a
// fake.
type oidcStateRepo interface {
	PutOIDCLoginState(ctx context.Context, state string, s db.OIDCLoginState, ttl time.Duration) error
	PopOIDCLoginState(ctx context.Context, state string) (db.OIDCLoginState, bool, error)
}

// PostgresStateStore is a StateStore backed by the oidc_login_states table, so OIDC login
// state is shared across all spire-server instances behind a load balancer.
type PostgresStateStore struct {
	repo oidcStateRepo
}

// NewPostgresStateStore builds a Postgres-backed OIDC state store.
func NewPostgresStateStore(repo oidcStateRepo) *PostgresStateStore {
	return &PostgresStateStore{repo: repo}
}

// Put implements StateStore.
func (p *PostgresStateStore) Put(ctx context.Context, state string, s AuthState, ttl time.Duration) error {
	return p.repo.PutOIDCLoginState(ctx, state, db.OIDCLoginState{
		CodeVerifier: s.CodeVerifier,
		Nonce:        s.Nonce,
		RedirectURI:  s.RedirectURI,
		CreatedAt:    s.CreatedAt,
	}, ttl)
}

// Pop implements StateStore.
func (p *PostgresStateStore) Pop(ctx context.Context, state string) (AuthState, bool, error) {
	ls, found, err := p.repo.PopOIDCLoginState(ctx, state)
	if err != nil || !found {
		return AuthState{}, found, err
	}
	return AuthState{
		CodeVerifier: ls.CodeVerifier,
		Nonce:        ls.Nonce,
		RedirectURI:  ls.RedirectURI,
		CreatedAt:    ls.CreatedAt,
	}, true, nil
}
