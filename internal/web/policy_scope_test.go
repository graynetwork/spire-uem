package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func requestAs(u *types.AdminUser) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", nil)
	return req.WithContext(context.WithValue(req.Context(), AdminUserObjCtxKey, u))
}

func TestPolicyTargetsAllowed_Tags(t *testing.T) {
	h := &Handler{}
	scoped := &types.AdminUser{Role: types.RoleSecurityAdmin, AllowedTags: []string{"eng", "lab"}}
	unscoped := &types.AdminUser{Role: types.RoleSecurityAdmin}
	cases := []struct {
		name string
		u    *types.AdminUser
		tags []string
		ok   bool
	}{
		{"unscoped admin may target the whole fleet", unscoped, nil, true},
		{"unscoped admin may target any tag", unscoped, []string{"finance"}, true},
		{"scoped admin may target own tag", scoped, []string{"eng"}, true},
		{"scoped admin may target all own tags", scoped, []string{"eng", "lab"}, true},
		{"scoped admin may not target the whole fleet", scoped, nil, false},
		{"scoped admin may not add another team's tag", scoped, []string{"eng", "finance"}, false},
		{"scoped admin may not target another team", scoped, []string{"finance"}, false},
	}
	for _, tc := range cases {
		if ok, _ := h.policyTargetsAllowed(requestAs(tc.u), tc.tags, nil); ok != tc.ok {
			t.Errorf("%s: allowed=%v want %v", tc.name, ok, tc.ok)
		}
	}
}

// End to end through the real handler: a scoped admin's fleet-wide policy is refused with
// 403 before anything is written (the handler has no repository, so reaching the write
// would panic).
func TestCreatePolicy_ScopedAdminFleetWideRefused(t *testing.T) {
	h := &Handler{}
	scoped := &types.AdminUser{Role: types.RoleSecurityAdmin, AllowedTags: []string{"eng"}}
	form := url.Values{
		"name":        {"fleet wide"},
		"policy_type": {string(types.PolicyTypePackagePresence)},
		"payload":     {`{"package_name":"htop"}`},
		"target_tags": {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), AdminUserObjCtxKey, scoped))
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("handler reached the repository instead of refusing: %v", p)
			}
		}()
		h.CreatePolicy(rec, req)
	}()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scoped admin fleet-wide policy: got %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
}
