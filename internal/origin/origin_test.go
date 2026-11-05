package origin

import (
	"encoding/json"
	"os"
	"testing"
)

func TestConformance(t *testing.T) {
	raw, err := os.ReadFile("testdata/origin-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct{ Input, Website, Origin string }
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Input, func(t *testing.T) {
			for _, mode := range []struct {
				parse func(string) (string, error)
				want  string
			}{{Website, v.Website}, {Parse, v.Origin}} {
				got, err := mode.parse(v.Input)
				if (err != nil) != (mode.want == "") || got != mode.want {
					t.Fatalf("got %q err=%v want=%q", got, err, mode.want)
				}
			}
		})
	}
}
