package web_test

import (
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

func TestGroupEditAllowed(t *testing.T) {
	unscopedGroup := &types.DeviceGroup{CreatorScopedTags: []string{}}
	engGroup := &types.DeviceGroup{CreatorScopedTags: []string{"eng"}}
	salesGroup := &types.DeviceGroup{CreatorScopedTags: []string{"sales"}}

	super := &types.AdminUser{Role: types.RoleSuperAdmin}
	auditor := &types.AdminUser{Role: types.RoleAuditor, AllowedTags: []string{"eng"}}
	unscopedSecAdmin := &types.AdminUser{Role: types.RoleSecurityAdmin}
	engSecAdmin := &types.AdminUser{Role: types.RoleSecurityAdmin, AllowedTags: []string{"eng"}}

	cases := []struct {
		name string
		user *types.AdminUser
		grp  *types.DeviceGroup
		want bool
	}{
		{"super edits any group", super, unscopedGroup, true},
		{"super edits scoped group", super, engGroup, true},
		{"auditor never tag-scoped; route RBAC blocks writes", auditor, engGroup, true},
		{"unscoped security admin edits any group", unscopedSecAdmin, engGroup, true},
		{"scoped admin edits own-scope group", engSecAdmin, engGroup, true},
		{"scoped admin cannot edit unscoped-created group", engSecAdmin, unscopedGroup, false},
		{"scoped admin cannot edit another scope's group", engSecAdmin, salesGroup, false},
		{"nil group refused for scoped admin", engSecAdmin, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := web.GroupEditAllowed(tc.user, tc.grp); got != tc.want {
				t.Errorf("GroupEditAllowed = %v, want %v", got, tc.want)
			}
		})
	}
}
