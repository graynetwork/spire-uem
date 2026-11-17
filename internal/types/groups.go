package types

import (
	"encoding/json"
	"time"
)

// GroupKind distinguishes a group usable for policy/application assignment from a saved
// fleet query that is view/export only.
type GroupKind string

const (
	// GroupKindTarget groups can be referenced by policies and applications for targeting.
	GroupKindTarget GroupKind = "target"
	// GroupKindQuery groups are saved fleet queries: searchable and exportable, never a
	// targeting selector.
	GroupKindQuery GroupKind = "query"
)

// ValidGroupKind reports whether k is a recognised group kind.
func ValidGroupKind(k GroupKind) bool {
	return k == GroupKindTarget || k == GroupKindQuery
}

// DeviceGroup is a dynamic device group or saved fleet query.
//
// Membership is (Rule matches OR device is in IncludeDeviceIDs) AND NOT in ExcludeDeviceIDs.
// A nil/empty Rule contributes no rule-matched devices; such a group is purely a static
// include/exclude list. Membership is materialised into group_memberships and recomputed
// after a device checks in, periodically, and whenever the group is saved.
type DeviceGroup struct {
	ID               string          `json:"id" db:"id"`
	Name             string          `json:"name" db:"name"`
	Description      string          `json:"description" db:"description"`
	Kind             GroupKind       `json:"kind" db:"kind"`
	Rule             json.RawMessage `json:"rule,omitempty" db:"rule"` // nil when there is no rule
	IncludeDeviceIDs []string        `json:"include_device_ids" db:"include_device_ids"`
	ExcludeDeviceIDs []string        `json:"exclude_device_ids" db:"exclude_device_ids"`
	CreatedBy        string          `json:"created_by" db:"created_by"`
	// CreatorScopedTags records the allowed_tags of the admin who created the group, so an
	// unscoped-created group can be told apart from a scoped-created one. Empty means the
	// group was created by an unscoped admin (SUPER_ADMIN, AUDITOR, or an operator without
	// allowed_tags). A scoped admin may not edit an unscoped admin's group.
	CreatorScopedTags []string  `json:"creator_scoped_tags" db:"creator_scoped_tags"`
	MemberCount       int       `json:"member_count" db:"-"`
	LastRuleError     string    `json:"last_rule_error,omitempty" db:"last_rule_error"`
	LastEvaluatedAt   *time.Time `json:"last_evaluated_at,omitempty" db:"last_evaluated_at"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// CreatedByScoped reports whether the group was created by a tag-scoped admin.
func (g DeviceGroup) CreatedByScoped() bool { return len(g.CreatorScopedTags) > 0 }

// GroupMembershipEvent is one entry in a group's bounded membership history: a device that
// entered or left the group, when, and why.
type GroupMembershipEvent struct {
	ID        int64     `json:"id" db:"id"`
	GroupID   string    `json:"group_id" db:"group_id"`
	DeviceID  string    `json:"device_id" db:"device_id"`
	Hostname  string    `json:"hostname" db:"hostname"`
	Entered   bool      `json:"entered" db:"entered"` // true = joined, false = left
	Reason    string    `json:"reason" db:"reason"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// GroupPreviewResult is returned by the rule preview endpoint: a total count plus the first
// page of matching devices, computed against a rule that has not been saved.
type GroupPreviewResult struct {
	Count   int            `json:"count"`
	Devices []DeviceGroupMember `json:"devices"`
}

// DeviceGroupMember is a compact device row for group member listings and previews.
type DeviceGroupMember struct {
	DeviceID string   `json:"device_id"`
	Hostname string   `json:"hostname"`
	Status   string   `json:"status"`
	Tags     []string `json:"tags"`
}
