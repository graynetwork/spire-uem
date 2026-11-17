package types

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDeviceAttributeValidate(t *testing.T) {
	big := json.RawMessage(`"` + strings.Repeat("x", MaxAttributeValue) + `"`)
	jsonAttr, _ := JSONAttr("sw.listening_ports", []int{22, 443})
	cases := []struct {
		name string
		a    DeviceAttribute
		ok   bool
	}{
		{"string", StringAttr("hw.cpu.model", "Ryzen 7"), true},
		{"integer", IntAttr("hw.memory_mb", 32768), true},
		{"boolean", BoolAttr("sec.secure_boot", true), true},
		{"datetime", TimeAttr("hw.bios.date", time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)), true},
		{"json", jsonAttr, true},
		{"bad key uppercase", StringAttr("HW.cpu", "x"), false},
		{"bad key trailing dot", StringAttr("hw.", "x"), false},
		{"bad key path", StringAttr("../etc", "x"), false},
		{"float as integer", DeviceAttribute{Key: "hw.x", Type: AttrInteger, Value: json.RawMessage(`1.5`)}, false},
		{"string as boolean", DeviceAttribute{Key: "hw.x", Type: AttrBoolean, Value: json.RawMessage(`"true"`)}, false},
		{"non-RFC3339 datetime", DeviceAttribute{Key: "hw.x", Type: AttrDatetime, Value: json.RawMessage(`"yesterday"`)}, false},
		{"unknown type", DeviceAttribute{Key: "hw.x", Type: "float", Value: json.RawMessage(`1`)}, false},
		{"empty value", DeviceAttribute{Key: "hw.x", Type: AttrString}, false},
		{"too large", DeviceAttribute{Key: "hw.x", Type: AttrString, Value: big}, false},
	}
	for _, tc := range cases {
		if err := tc.a.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: Validate() err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestAttributeSources(t *testing.T) {
	for _, s := range []string{AttrSourceInventory, AttrSourceSystem, SensorSource("disk_health"), SensorSource("vpn-client.v2")} {
		if !ValidAttributeSource(s) {
			t.Errorf("source %q should be valid", s)
		}
	}
	for _, s := range []string{"", "Inventory", "sensor:", "sensor:a b", "a:b:c"} {
		if ValidAttributeSource(s) {
			t.Errorf("source %q should be invalid", s)
		}
	}
}
