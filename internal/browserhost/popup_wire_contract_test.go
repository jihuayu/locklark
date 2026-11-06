package browserhost

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The extension tests load this exact fixture too. This checks its requests
// against the production decoder and its responses against the production
// encoder, so two independent mock implementations cannot agree on a wrong key.
func TestPopupFieldValueCrossLanguageContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "browser-extension", "test", "fixtures", "field-value-wire.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Requests  map[string]json.RawMessage `json:"requests"`
		Responses map[string]json.RawMessage `json:"responses"`
	}
	if json.Unmarshal(raw, &fixture) != nil || len(fixture.Requests) != 3 || len(fixture.Responses) != 3 {
		t.Fatal("invalid shared protocol fixture")
	}
	for name, requestJSON := range fixture.Requests {
		t.Run(name, func(t *testing.T) {
			request, err := ReadRequest(bytes.NewReader(frame(string(requestJSON))))
			if err != nil {
				t.Fatal("extension request rejected by native decoder", err)
			}
			var response Response
			if json.Unmarshal(fixture.Responses[name], &response) != nil || response.FieldValue == "" {
				t.Fatal("extension response fixture does not match native DTO")
			}
			if response.ID != request.ID || response.ItemID != request.ItemID || response.Revision != request.Revision || response.Field != request.Field {
				t.Fatal("fixture response is not bound to its request")
			}
			if (request.Type == "item-copy-field") != response.Copied || (request.FieldAction == "copy") != response.Copied {
				t.Fatal("copy/reveal action mismatch")
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			var actual, expected map[string]any
			if json.Unmarshal(encoded, &actual) != nil || json.Unmarshal(fixture.Responses[name], &expected) != nil || !reflect.DeepEqual(actual, expected) {
				t.Fatal("native response keys/values differ from shared extension fixture")
			}
		})
	}
}
