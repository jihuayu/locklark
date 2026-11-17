package brokerlease

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestBrokerLeaseMetadataClosedInputType(t *testing.T) {
	typ := reflect.TypeOf(Metadata{})
	if typ.Kind() != reflect.Struct {
		t.Fatal("metadata input is not a struct")
	}
	names := []string{"Event", "Reason", "BindingChecks", "NonceConsumed"}
	if typ.NumField() != len(names) {
		t.Fatal("metadata input has an unexpected field count")
	}
	for i, name := range names {
		field := typ.Field(i)
		if field.Name != name {
			t.Fatal("metadata input has an unexpected field name")
		}
		if field.Type.Kind() != reflect.Uint8 && field.Type.Kind() != reflect.Uint16 {
			t.Fatal("metadata input has a non-count field type")
		}
	}

	fn := reflect.TypeOf(Encode)
	if fn.Kind() != reflect.Func || fn.NumIn() != 1 || fn.In(0) != typ {
		t.Fatal("encoder does not accept exactly Metadata")
	}
	if fn.NumOut() != 2 || fn.Out(0) != reflect.TypeOf([]byte{}) || fn.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatal("encoder does not return bytes and a fixed error")
	}
}

func TestBrokerLeaseMetadataValidEnumsBounded(t *testing.T) {
	for event := eventFirst; event <= eventLast; event++ {
		for reason := reasonFirst; reason <= reasonLast; reason++ {
			m := Metadata{
				Event:         event,
				Reason:        reason,
				BindingChecks: MaxBindingChecks,
				NonceConsumed: MaxAdmissionsPerLease,
			}
			raw, err := Encode(m)
			if err != nil {
				t.Fatal("valid metadata rejected")
			}
			if len(raw) == 0 || len(raw) > MaxRecordBytes {
				t.Fatal("valid metadata exceeded the record bound")
			}
			if !json.Valid(raw) {
				t.Fatal("valid metadata was not valid JSON")
			}
			again, err := Encode(m)
			if err != nil {
				t.Fatal("valid metadata rejected on repeat")
			}
			if !bytes.Equal(raw, again) {
				t.Fatal("valid metadata encoding was not deterministic")
			}
		}
	}
}

func TestBrokerLeaseMetadataMaxRecord(t *testing.T) {
	m := Metadata{
		Event:         EventLeaseOutcomeUnknown,
		Reason:        ReasonUnknownOutcome,
		BindingChecks: MaxBindingChecks,
		NonceConsumed: MaxAdmissionsPerLease,
	}
	first, err := Encode(m)
	if err != nil {
		t.Fatal("max metadata rejected")
	}
	second, err := Encode(m)
	if err != nil {
		t.Fatal("max metadata rejected on repeat")
	}
	if len(first) > MaxRecordBytes {
		t.Fatal("max metadata exceeded the record bound")
	}
	if !bytes.Equal(first, second) {
		t.Fatal("max metadata encoding was not deterministic")
	}
	if !json.Valid(first) {
		t.Fatal("max metadata was not valid JSON")
	}
}

func TestBrokerLeaseMetadataRecordShape(t *testing.T) {
	m := Metadata{
		Event:         EventLeaseOutcomeUnknown,
		Reason:        ReasonUnknownOutcome,
		BindingChecks: MaxBindingChecks,
		NonceConsumed: MaxAdmissionsPerLease,
	}
	raw, err := Encode(m)
	if err != nil {
		t.Fatal("shape metadata rejected")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("shape metadata was not one JSON object")
	}
	keys := []string{"v", "event", "reason", "binding_checks", "nonce_consumed"}
	if len(fields) != len(keys) {
		t.Fatal("shape metadata had unexpected keys")
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			t.Fatal("shape metadata missed a fixed key")
		}
	}
	var version int
	if json.Unmarshal(fields["v"], &version) != nil || version != MetadataVersion {
		t.Fatal("shape metadata had the wrong schema version")
	}
	var event, reason string
	if json.Unmarshal(fields["event"], &event) != nil || event == "" {
		t.Fatal("shape metadata had a non-string event")
	}
	if json.Unmarshal(fields["reason"], &reason) != nil || reason == "" {
		t.Fatal("shape metadata had a non-string reason")
	}
	var checks uint8
	if json.Unmarshal(fields["binding_checks"], &checks) != nil || checks != MaxBindingChecks {
		t.Fatal("shape metadata had the wrong binding-check count")
	}
	var consumed uint16
	if json.Unmarshal(fields["nonce_consumed"], &consumed) != nil || consumed != MaxAdmissionsPerLease {
		t.Fatal("shape metadata had the wrong nonce count")
	}
}

func TestBrokerLeaseMetadataRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		m    Metadata
		want error
	}{
		{"event_zero", Metadata{Event: EventUnknown, Reason: ReasonNone}, ErrMetadataEvent},
		{"event_unknown", Metadata{Event: Event(255), Reason: ReasonNone}, ErrMetadataEvent},
		{"reason_zero", Metadata{Event: EventLeaseUsed, Reason: ReasonUnknown}, ErrMetadataReason},
		{"reason_unknown", Metadata{Event: EventLeaseUsed, Reason: Reason(255)}, ErrMetadataReason},
		{"binding_checks", Metadata{Event: EventLeaseUsed, Reason: ReasonNone, BindingChecks: MaxBindingChecks + 1}, ErrMetadataBindingChecks},
		{"nonce_consumed", Metadata{Event: EventLeaseUsed, Reason: ReasonNone, NonceConsumed: MaxAdmissionsPerLease + 1}, ErrMetadataNonceConsumed},
	}
	for _, tc := range cases {
		raw, err := Encode(tc.m)
		if err != tc.want {
			t.Fatalf("%s: wrong failure class", tc.name)
		}
		if len(raw) != 0 {
			t.Fatalf("%s: rejection returned bytes", tc.name)
		}
	}
}
