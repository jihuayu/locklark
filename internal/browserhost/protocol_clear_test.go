package browserhost

import "testing"

func TestResponseClearWipesFieldValueGeneratedPasswordAndAttachmentData(t *testing.T) {
	response := Response{
		V:                 1,
		ID:                reqID(999),
		Type:              "field-value",
		FieldValue:        "synthetic-field-value",
		GeneratedPassword: "synthetic-generated-password",
		Data:              "c3ludGhldGljLWF0dGFjaG1lbnQtZGF0YQ==",
	}

	response.Clear()

	if response.FieldValue != "" || response.GeneratedPassword != "" || response.Data != "" {
		t.Fatalf("Clear retained field=%q generated=%q data=%q", response.FieldValue, response.GeneratedPassword, response.Data)
	}
}
