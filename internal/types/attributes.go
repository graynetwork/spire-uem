package types

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// AttributeType is the declared type of a device attribute value.
type AttributeType string

const (
	AttrString   AttributeType = "string"
	AttrInteger  AttributeType = "integer"
	AttrBoolean  AttributeType = "boolean"
	AttrDatetime AttributeType = "datetime" // RFC 3339, UTC
	AttrJSON     AttributeType = "json"
)

// Attribute sources. A source owns the keys it writes; writers can only replace or remove
// their own keys. Sensors use "sensor:<sensor-name>".
const (
	AttrSourceInventory = "inventory"
	AttrSourceSystem    = "system"
	AttrSourceSensorPfx = "sensor:"
)

// Key namespaces. Inventory owns hw., sw., net., sec. and os.; sensors write sensor.<name>.
// Group rules address built-in device columns as device.<field> and attributes by key.
const (
	AttrKeySensorPrefix = "sensor."
	MaxAttributeValue   = 4096 // bytes of encoded JSON value
	MaxAttributesPerSet = 512
)

var (
	attrKeyRe    = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)
	attrSourceRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(:[a-z0-9_.-]+)?$`)
)

// DeviceAttribute is one typed value for one device.
type DeviceAttribute struct {
	DeviceID  string          `json:"device_id,omitempty"`
	Key       string          `json:"key"`
	Type      AttributeType   `json:"type"`
	Value     json.RawMessage `json:"value"`
	Source    string          `json:"source,omitempty"`
	UpdatedAt time.Time       `json:"updated_at,omitempty"`
}

// AttributeKeyInfo summarises one key across the fleet, for rule builders and search UIs.
type AttributeKeyInfo struct {
	Key         string        `json:"key"`
	Type        AttributeType `json:"type"`
	Source      string        `json:"source"`
	DeviceCount int           `json:"device_count"`
}

// ValidAttributeKey reports whether key is a well-formed attribute key.
func ValidAttributeKey(key string) bool {
	return len(key) <= 128 && attrKeyRe.MatchString(key)
}

// ValidAttributeSource reports whether source is a well-formed attribute source.
func ValidAttributeSource(source string) bool {
	return len(source) <= 128 && attrSourceRe.MatchString(source)
}

// SensorSource returns the attribute source for a named sensor.
func SensorSource(sensorName string) string { return AttrSourceSensorPfx + sensorName }

// Validate checks the key, the type, the size, and that Value decodes as the declared type.
func (a DeviceAttribute) Validate() error {
	if !ValidAttributeKey(a.Key) {
		return fmt.Errorf("invalid attribute key %q", a.Key)
	}
	if len(a.Value) == 0 {
		return fmt.Errorf("attribute %s has no value", a.Key)
	}
	if len(a.Value) > MaxAttributeValue {
		return fmt.Errorf("attribute %s value is %d bytes, limit %d", a.Key, len(a.Value), MaxAttributeValue)
	}
	switch a.Type {
	case AttrString:
		var s string
		if err := json.Unmarshal(a.Value, &s); err != nil {
			return fmt.Errorf("attribute %s: not a string", a.Key)
		}
	case AttrInteger:
		var n json.Number
		dec := json.NewDecoder(strings.NewReader(string(a.Value)))
		dec.UseNumber()
		if err := dec.Decode(&n); err != nil {
			return fmt.Errorf("attribute %s: not an integer", a.Key)
		}
		if _, err := n.Int64(); err != nil {
			return fmt.Errorf("attribute %s: not an integer", a.Key)
		}
	case AttrBoolean:
		var b bool
		if err := json.Unmarshal(a.Value, &b); err != nil {
			return fmt.Errorf("attribute %s: not a boolean", a.Key)
		}
	case AttrDatetime:
		var s string
		if err := json.Unmarshal(a.Value, &s); err != nil {
			return fmt.Errorf("attribute %s: datetime must be an RFC 3339 string", a.Key)
		}
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return fmt.Errorf("attribute %s: datetime must be RFC 3339", a.Key)
		}
	case AttrJSON:
		if !json.Valid(a.Value) {
			return fmt.Errorf("attribute %s: invalid JSON", a.Key)
		}
	default:
		return fmt.Errorf("attribute %s: unknown type %q", a.Key, a.Type)
	}
	return nil
}

// StringAttr, IntAttr, BoolAttr, TimeAttr and JSONAttr build typed attributes.
func StringAttr(key, v string) DeviceAttribute {
	b, _ := json.Marshal(v)
	return DeviceAttribute{Key: key, Type: AttrString, Value: b}
}

func IntAttr(key string, v int64) DeviceAttribute {
	b, _ := json.Marshal(v)
	return DeviceAttribute{Key: key, Type: AttrInteger, Value: b}
}

func BoolAttr(key string, v bool) DeviceAttribute {
	b, _ := json.Marshal(v)
	return DeviceAttribute{Key: key, Type: AttrBoolean, Value: b}
}

func TimeAttr(key string, v time.Time) DeviceAttribute {
	b, _ := json.Marshal(v.UTC().Format(time.RFC3339))
	return DeviceAttribute{Key: key, Type: AttrDatetime, Value: b}
}

func JSONAttr(key string, v any) (DeviceAttribute, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return DeviceAttribute{}, err
	}
	return DeviceAttribute{Key: key, Type: AttrJSON, Value: b}, nil
}
