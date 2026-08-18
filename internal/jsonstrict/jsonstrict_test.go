package jsonstrict

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodeOneRejectsAmbiguousAndNonCanonicalInput(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{"duplicate top-level key", []byte(`{"value":"first","value":"second"}`)},
		{"duplicate nested key", []byte(`{"nested":{"value":"first","value":"second"}}`)},
		{"invalid UTF-8", []byte{'{', '"', 'v', 'a', 'l', 'u', 'e', '"', ':', '"', 0xff, '"', '}'}},
		{"unpaired surrogate", []byte(`{"value":"\ud800"}`)},
		{"unknown field", []byte(`{"value":"safe","extra":true}`)},
		{"trailing value", []byte(`{"value":"safe"} {}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var destination struct {
				Value  string `json:"value"`
				Nested struct {
					Value string `json:"value"`
				} `json:"nested,omitempty"`
			}
			if err := DecodeOne(test.raw, &destination); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
}

func TestDecodeOneAcceptsOneStrictValue(t *testing.T) {
	var destination struct {
		Value string `json:"value"`
	}
	if err := DecodeOne([]byte("  {\n\t\"value\":\"safe\"\n}\n"), &destination); err != nil {
		t.Fatal(err)
	}
	if destination.Value != "safe" {
		t.Fatalf("decoded value=%q", destination.Value)
	}
	if err := DecodeOne([]byte(`{"value":"\ud83d\udd12 and \ufffd"}`), &destination); err != nil {
		t.Fatalf("valid surrogate pair or literal replacement character rejected: %v", err)
	}
}

func TestDecodeOneBoundsNestingBeforeRecursiveStackGrowth(t *testing.T) {
	if maxNestingDepth != 64 {
		t.Fatalf("nesting limit=%d, want 64", maxNestingDepth)
	}
	valueAtDepth := func(depth int) []byte {
		return []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
	}
	var destination any
	if err := DecodeOne(valueAtDepth(maxNestingDepth), &destination); err != nil {
		t.Fatalf("maximum supported nesting rejected: %v", err)
	}
	if err := DecodeOne(valueAtDepth(maxNestingDepth+1), &destination); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("over-depth JSON error=%v", err)
	}

	// Exercise every larger Airlock byte budget with an adversarial prefix. The
	// validator must stop at the same small depth rather than walking the body.
	for _, size := range []int{1 << 20, 2 << 20, 16 << 20} {
		raw := bytes.Repeat([]byte{'['}, size)
		if err := DecodeOne(raw, &destination); err == nil || !strings.Contains(err.Error(), "nesting depth") {
			t.Fatalf("%d-byte nested JSON error=%v", size, err)
		}
	}
}
