package canonical

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCanonicalizeSortsKeysAndPreservesArrayOrder(t *testing.T) {
	input := map[string]any{
		"b": []any{3, 2, 1},
		"a": map[string]any{
			"z": "last",
			"m": "middle",
		},
	}

	canonical, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}
	want := `{"a":{"m":"middle","z":"last"},"b":[3,2,1]}`
	if canonical != want {
		t.Fatalf("unexpected canonical json: got %s want %s", canonical, want)
	}
}

func TestCanonicalizeExcludingRemovesKeysRecursively(t *testing.T) {
	input := map[string]any{
		"name":      "doc",
		"signature": "outer",
		"nested": map[string]any{
			"signature": "inner",
			"value":     1,
		},
	}

	canonical, err := CanonicalizeExcluding(input, []string{"signature"})
	if err != nil {
		t.Fatalf("CanonicalizeExcluding failed: %v", err)
	}
	want := `{"name":"doc","nested":{"value":1}}`
	if canonical != want {
		t.Fatalf("unexpected canonical json with exclusions: got %s want %s", canonical, want)
	}
}

func TestCanonicalizeNormalizesJSONNumbers(t *testing.T) {
	decoder := json.NewDecoder(bytes.NewBufferString(`{"b":1e+09,"a":-0,"c":1.2300}`))
	decoder.UseNumber()
	var input map[string]any
	if err := decoder.Decode(&input); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	canonical, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}
	want := `{"a":0,"b":1e9,"c":1.23}`
	if canonical != want {
		t.Fatalf("unexpected normalized number output: got %s want %s", canonical, want)
	}
}
