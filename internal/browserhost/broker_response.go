package browserhost

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"github.com/jihuayu/locklark/internal/personal"
)

// The audited CLI-run reply is exactly one of:
//
//	{"v":1,"values_b64":{"<slot>":"<base64 of the exact prepared bytes>"},"receipt":{"status":...,"session":...,"intent":...,"target_digest":...}}
//	{"v":1,"error":"refused"} or {"v":1,"error":"unavailable"}
//
// Every slot value is encoded through encoding/json (so a JSON string can
// only describe exact bytes) and base64, and the receipt is encoded as its
// canonical JSON object. Both directions use these helpers, so one encoding
// is shared by the desktop writer and the CLI reader.
const (
	cliRunValuesField  = "values_b64"
	cliRunReceiptField = "receipt"
)

// The only error tokens that may ever be encoded. Both are fixed, secret-free
// classifications; anything else a callback or caller supplies is refused.
const (
	cliRunErrorRefused     = "refused"
	cliRunErrorUnavailable = "unavailable"
)

// validCLIRunError reports whether token is exactly one of the two fixed
// error classifications.
func validCLIRunError(token string) bool {
	return token == cliRunErrorRefused || token == cliRunErrorUnavailable
}

// cliRunResponseWire is the concrete success reply. Its tag names are the
// exact wire names; every field is canonicalized before encoding.
type cliRunResponseWire struct {
	V       int                                  `json:"v"`
	Values  map[string][]byte                    `json:"values_b64"`
	Receipt personal.RunBundlePreparationReceipt `json:"receipt"`
}

// marshalCLIRunResponse encodes one error reply, or one audited values reply
// with its canonical receipt. It refuses anything else with the generic
// response error: the legacy Values payload in any combination, an error
// alongside values, any error token other than the exact refused or
// unavailable classification, values without a canonical receipt, an empty
// slot name, or a nil value. The caller-owned response is not modified.
func marshalCLIRunResponse(resp CLIRunBrokerResponse) ([]byte, error) {
	if len(resp.Values) != 0 {
		return nil, errCLIRunResponse
	}
	if resp.Error != "" {
		if !validCLIRunError(resp.Error) || len(resp.PreparedValues) != 0 || resp.Receipt != (personal.RunBundlePreparationReceipt{}) {
			return nil, errCLIRunResponse
		}
		return json.Marshal(cliRunReply{V: 1, Error: resp.Error})
	}
	if resp.V != 1 || len(resp.PreparedValues) == 0 || !validCLIRunReceipt(resp.Receipt) {
		return nil, errCLIRunResponse
	}
	return marshalCLIRunValues(resp.PreparedValues, resp.Receipt)
}

// marshalCLIRunValues encodes one values_b64 success reply after checking every
// slot name and buffer, so the bound path used by the serving callback cannot
// reach the wire with an unaudited value shape.
func marshalCLIRunValues(values map[string][]byte, receipt personal.RunBundlePreparationReceipt) ([]byte, error) {
	if len(values) == 0 || !validCLIRunReceipt(receipt) {
		return nil, errCLIRunResponse
	}
	for slot, value := range values {
		if slot == "" || value == nil {
			return nil, errCLIRunResponse
		}
	}
	return json.Marshal(cliRunResponseWire{V: 1, Values: values, Receipt: receipt})
}

// clearCLIRunResponse zeroes every decoded value buffer of resp, blanks the
// legacy string payload, and replaces the response, so a served request leaves
// no secret in scope.
func clearCLIRunResponse(resp *CLIRunBrokerResponse) {
	if resp == nil {
		return
	}
	for slot, value := range resp.PreparedValues {
		clear(value)
		delete(resp.PreparedValues, slot)
	}
	for slot := range resp.Values {
		resp.Values[slot] = ""
	}
	*resp = CLIRunBrokerResponse{}
}

// clearCLIRunValueMap zeroes every buffer in values and empties the map.
func clearCLIRunValueMap(values map[string][]byte) {
	for slot, value := range values {
		clear(value)
		delete(values, slot)
	}
}

// validCLIRunValues reports whether values carries exactly one non-nil buffer
// for each requested target slot and nothing else.
func validCLIRunValues(targets []personal.CLIBrokerTarget, values map[string][]byte) bool {
	if len(values) != len(targets) {
		return false
	}
	for _, target := range targets {
		if value, ok := values[target.Slot]; !ok || value == nil {
			return false
		}
	}
	return true
}

// validCLIRunReceipt reports whether receipt is a canonical preparation
// receipt: the explicit preparation status, a canonical 32-hex session ID, and
// two canonical 64-hex digests. It is checked here independently of personal so
// the broker never trusts a receipt it cannot itself verify. A malformed
// receipt means the audited intent was not established, so no value may pass.
func validCLIRunReceipt(receipt personal.RunBundlePreparationReceipt) bool {
	return receipt.Status == personal.RunBundlePreparationStatus &&
		lowerHex(receipt.Session, 32) && lowerHex(receipt.Intent, 64) && lowerHex(receipt.TargetDigest, 64)
}

// canonicalCLIRunReceipt reports whether raw is the exact canonical encoding
// of a valid receipt: one object, no duplicate or unknown keys, canonical
// values, and the same bytes json.Marshal would produce. Every raw copy is
// cleared before returning.
func canonicalCLIRunReceipt(raw json.RawMessage) bool {
	keys, copies, ok := strictJSONObject(raw)
	defer clearCLIRunRawMessages(copies)
	if !ok || len(keys) != 4 {
		return false
	}
	for _, field := range []string{"status", "session", "intent", "target_digest"} {
		if _, present := keys[field]; !present {
			return false
		}
	}
	var receipt personal.RunBundlePreparationReceipt
	if json.Unmarshal(raw, &receipt) != nil || !validCLIRunReceipt(receipt) {
		return false
	}
	again, e := json.Marshal(receipt)
	defer clear(again)
	return e == nil && bytes.Equal(again, raw)
}

// decodeCLIRunReceipt strictly decodes the receipt member.
func decodeCLIRunReceipt(raw json.RawMessage) (personal.RunBundlePreparationReceipt, bool) {
	if !canonicalCLIRunReceipt(raw) {
		return personal.RunBundlePreparationReceipt{}, false
	}
	var receipt personal.RunBundlePreparationReceipt
	if json.Unmarshal(raw, &receipt) != nil {
		return personal.RunBundlePreparationReceipt{}, false
	}
	return receipt, true
}

// decodeCLIRunValues strictly decodes the values member for targets: one
// object, no duplicate slot names, and every value exactly one unescaped,
// canonical standard base64 string that decodes the prepared bytes. A null, a
// non-string, an escaped string, invalid base64, non-canonical base64 (any
// string base64 does not re-encode to exactly), or any slot outside the
// requested set is refused. Empty bytes are accepted when the decoded slice is
// non-nil. A partial decode is cleared before it is rejected, every partial
// set is zeroed before returning false, and every raw copy is cleared.
func decodeCLIRunValues(raw json.RawMessage, targets []personal.CLIBrokerTarget) (values map[string][]byte, ok bool) {
	// strictJSONObject reads nil as a null document, so the member is required
	// to be present and not null before it is parsed.
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, false
	}
	_, slots, parsed := strictJSONObject(raw)
	defer clearCLIRunRawMessages(slots)
	if !parsed {
		return nil, false
	}
	values = make(map[string][]byte, len(slots))
	defer func() {
		if !ok {
			clearCLIRunValueMap(values)
			values = nil
		}
	}()
	for slot, encoded := range slots {
		if slot == "" {
			return nil, false
		}
		// A base64 value is one unescaped JSON string. A null, number, object,
		// array or boolean is refused; encoding/json must not be allowed to
		// turn a null into an empty string, which would decode as a non-nil
		// empty slice. An escape sequence is refused too: canonical base64
		// never needs one, and decoding the raw member bytes keeps the only
		// intermediate copy a []byte that is cleared on every failure.
		if len(encoded) < 2 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' || bytes.IndexByte(encoded, '\\') >= 0 {
			return nil, false
		}
		text := encoded[1 : len(encoded)-1]
		// Encoding.Decode returns the bytes it decoded before a defect
		// alongside the error and always allocates, so they are cleared
		// before rejecting.
		value := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
		n, e := base64.StdEncoding.Decode(value, text)
		if e != nil {
			clear(value)
			return nil, false
		}
		value = value[:n]
		// Canonical only: re-encoding must reproduce exactly the raw base64
		// bytes the member carried (standard alphabet, required padding, no
		// stray line break, no trailing zero bits). Both buffers are cleared
		// when they differ.
		again := make([]byte, base64.StdEncoding.EncodedLen(len(value)))
		base64.StdEncoding.Encode(again, value)
		canonical := bytes.Equal(again, text)
		clear(again)
		if !canonical {
			clear(value)
			return nil, false
		}
		values[slot] = value
	}
	if !validCLIRunValues(targets, values) {
		return nil, false
	}
	return values, true
}

// decodeCLIRunResponse decodes one audited values reply for targets. It accepts
// exactly the three-key success object above: no error member, no unknown
// field, a canonical receipt, and base64 values with exactly the target slots
// and no nil values, with no trailing data. Any defect returns the generic
// response error and leaves no decoded bytes behind.
func decodeCLIRunResponse(raw []byte, targets []personal.CLIBrokerTarget) (CLIRunBrokerResponse, error) {
	keys, copies, ok := strictJSONObject(raw)
	defer clearCLIRunRawMessages(copies)
	if !ok || keys == nil {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	for _, field := range []string{"v", cliRunValuesField, cliRunReceiptField} {
		if _, present := keys[field]; !present {
			return CLIRunBrokerResponse{}, errCLIRunResponse
		}
	}
	if len(keys) != 3 {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	var v int
	if json.Unmarshal(copies["v"], &v) != nil || v != 1 {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	receipt, ok := decodeCLIRunReceipt(copies[cliRunReceiptField])
	if !ok {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	values, ok := decodeCLIRunValues(copies[cliRunValuesField], targets)
	if !ok {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	return CLIRunBrokerResponse{V: 1, PreparedValues: values, Receipt: receipt}, nil
}
