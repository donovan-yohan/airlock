package paging

import (
	"strings"
	"testing"
	"time"
)

func TestPageUsesStableKeysetAfterCursorRecordIsPruned(t *testing.T) {
	older := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Minute)
	keys := []Key{
		{ID: "req_a", CreatedAt: older},
		{ID: "req_c", CreatedAt: newer},
		{ID: "req_b", CreatedAt: newer},
	}
	first, cursor, err := Page(keys, 2, "")
	if err != nil || len(first) != 2 || first[0].ID != "req_c" || first[1].ID != "req_b" || !ValidCursor(cursor) {
		t.Fatalf("first page=%v cursor=%q err=%v", first, cursor, err)
	}

	// The cursor record disappears between requests. Keyset pagination still
	// resumes strictly after its former position instead of returning an error.
	remaining := []Key{{ID: "req_c", CreatedAt: newer}, {ID: "req_a", CreatedAt: older}}
	second, next, err := Page(remaining, 2, cursor)
	if err != nil || len(second) != 1 || second[0].ID != "req_a" || next != "" {
		t.Fatalf("second page=%v cursor=%q err=%v", second, next, err)
	}
}

func TestPageRejectsInvalidBoundsAndCursor(t *testing.T) {
	keys := []Key{{ID: "req_a", CreatedAt: time.Now().UTC()}}
	for _, limit := range []int{0, MaxPage + 1} {
		if _, _, err := Page(keys, limit, ""); err == nil {
			t.Fatalf("limit %d accepted", limit)
		}
	}
	if _, _, err := Page(keys, 1, "req_unknown"); err == nil {
		t.Fatal("malformed cursor accepted")
	}
}

func TestValidCursorRejectsOversizeAndControlText(t *testing.T) {
	cursor, err := encodeCursor(Key{
		ID:        "req_" + strings.Repeat("x", 80),
		CreatedAt: time.Date(2026, 8, 15, 0, 0, 0, 123, time.UTC),
	})
	if err != nil || len(cursor) > MaxCursorBytes || !ValidCursor(cursor) {
		t.Fatalf("valid maximum-size cursor=%q err=%v", cursor, err)
	}
	if !ValidCursor("") {
		t.Fatal("empty optional cursor rejected")
	}
	for _, value := range []string{
		strings.Repeat("x", MaxCursorBytes+1),
		"req_line\nbreak",
		"req_escape\x1b[31m",
		string([]byte{0xff}),
	} {
		if ValidCursor(value) {
			t.Fatalf("unsafe cursor %q accepted", value)
		}
	}
}

func TestValidatePageRejectsInvalidContinuation(t *testing.T) {
	oldest := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	keys := []Key{
		{ID: "req_c", CreatedAt: oldest.Add(2 * time.Second)},
		{ID: "req_b", CreatedAt: oldest.Add(time.Second)},
		{ID: "req_a", CreatedAt: oldest},
	}
	cursorFor := func(t *testing.T, key Key) string {
		t.Helper()
		cursor, err := CursorFor(key)
		if err != nil {
			t.Fatal(err)
		}
		return cursor
	}
	if err := ValidatePage(keys[:2], 2, "", cursorFor(t, keys[1])); err != nil {
		t.Fatalf("valid nonterminal page: %v", err)
	}
	for name, test := range map[string]struct {
		page   []Key
		cursor string
		next   string
	}{
		"empty nonterminal": {nil, "", cursorFor(t, keys[0])},
		"short nonterminal": {keys[:1], "", cursorFor(t, keys[0])},
		"mismatched cursor": {keys[:2], "", cursorFor(t, keys[2])},
		"nonforward cycle":  {keys[:2], cursorFor(t, keys[1]), cursorFor(t, keys[1])},
		"unordered records": {[]Key{keys[1], keys[0]}, "", cursorFor(t, keys[0])},
		"oversized page":    {keys, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePage(test.page, 2, test.cursor, test.next); err == nil {
				t.Fatal("invalid continuation accepted")
			}
		})
	}
}
