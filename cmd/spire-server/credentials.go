package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// enforceAdminCredentials refuses to run with known-default administrator credentials.
//
//   - A configured break-glass password must pass config.ValidateBreakGlassPassword.
//   - Any active LOCAL account still using the migration-seeded password is a known
//     super-admin credential. If it is the break-glass username and a strong break-glass
//     password is configured, its password is rotated to that value; otherwise startup fails.
//   - At least one way to sign in must remain (an active account or the break-glass account).
func enforceAdminCredentials(ctx context.Context, repo *db.Repository, cfg config.ServerConfig) error {
	if err := config.ValidateBreakGlassPassword(cfg.AdminPassword); err != nil {
		return err
	}

	users, err := repo.ListAdminUsers(ctx)
	if err != nil {
		return fmt.Errorf("list admin users: %w", err)
	}

	var stillDefault []string
	active := 0
	for _, u := range users {
		if !u.IsActive {
			continue
		}
		active++
		if u.AuthProvider != types.AuthProviderLocal || u.PasswordHash == "" {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(config.DefaultSeededAdminPassword)) != nil {
			continue
		}
		if cfg.BreakGlassEnabled() && strings.EqualFold(u.Username, cfg.AdminUsername) {
			pw := cfg.AdminPassword
			if _, err := repo.UpdateAdminUser(ctx, u.ID, types.UpdateUserRequest{Password: &pw}); err != nil {
				return fmt.Errorf("rotate default password for %q: %w", u.Username, err)
			}
			log.Printf("[spire-server] SECURITY: rotated the default seeded password of local account %q to the configured SPIRE_ADMIN_PASSWORD", u.Username)
			continue
		}
		stillDefault = append(stillDefault, u.Username)
	}

	if len(stillDefault) > 0 {
		return fmt.Errorf("local admin account(s) %v still use the default password %q; set a strong SPIRE_ADMIN_PASSWORD (min %d chars) to rotate the %q account, or change/disable these accounts",
			stillDefault, config.DefaultSeededAdminPassword, config.MinBreakGlassPasswordLen, cfg.AdminUsername)
	}
	if active == 0 && !cfg.BreakGlassEnabled() {
		return fmt.Errorf("no active admin accounts and no break-glass account; set SPIRE_ADMIN_PASSWORD (min %d chars) to bootstrap access", config.MinBreakGlassPasswordLen)
	}
	if cfg.BreakGlassEnabled() {
		log.Printf("[spire-server] static break-glass account %q is ENABLED (SPIRE_ADMIN_PASSWORD set)", cfg.AdminUsername)
	} else {
		log.Printf("[spire-server] static break-glass account is disabled (SPIRE_ADMIN_PASSWORD not set)")
	}
	return nil
}
