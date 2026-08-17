// Package paging defines Airlock's bounded, stable read contract.
package paging

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sort"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxPage        = 100
	DefaultPage    = 50
	MaxCursorBytes = 128
	cursorPrefix   = 12 // int64 Unix seconds followed by uint32 nanoseconds
)

var (
	errLimit  = errors.New("page limit out of bounds")
	errCursor = errors.New("invalid page cursor")
)

// Key identifies one record in the stable newest-first order: descending
// created_at, then descending ID.
type Key struct {
	ID        string
	CreatedAt time.Time
}

// Page sorts keys into stable newest-first order and returns the bounded page
// strictly after cursor. The cursor encodes the last returned ordering key, so
// pagination still advances if that record is pruned between requests. keys is
// sorted in place and the returned slice aliases it.
func Page(keys []Key, limit int, cursor string) ([]Key, string, error) {
	if limit < 1 || limit > MaxPage {
		return nil, "", errLimit
	}
	sort.Slice(keys, func(i, j int) bool { return newer(keys[i], keys[j]) })

	start := 0
	if cursor != "" {
		cursorKey, err := decodeCursor(cursor)
		if err != nil {
			return nil, "", err
		}
		start = sort.Search(len(keys), func(index int) bool {
			return older(keys[index], cursorKey)
		})
	}
	end := min(start+limit, len(keys))
	next := ""
	if end < len(keys) {
		var err error
		next, err = encodeCursor(keys[end-1])
		if err != nil {
			return nil, "", err
		}
	}
	return keys[start:end], next, nil
}

func newer(left, right Key) bool {
	if left.CreatedAt.Equal(right.CreatedAt) {
		return left.ID > right.ID
	}
	return left.CreatedAt.After(right.CreatedAt)
}

func older(left, right Key) bool {
	if left.CreatedAt.Equal(right.CreatedAt) {
		return left.ID < right.ID
	}
	return left.CreatedAt.Before(right.CreatedAt)
}

func encodeCursor(key Key) (string, error) {
	if key.CreatedAt.IsZero() || !validText(key.ID, MaxCursorBytes) {
		return "", errCursor
	}
	raw := make([]byte, cursorPrefix+len(key.ID))
	binary.BigEndian.PutUint64(raw[:8], uint64(key.CreatedAt.Unix()))
	binary.BigEndian.PutUint32(raw[8:cursorPrefix], uint32(key.CreatedAt.Nanosecond()))
	copy(raw[cursorPrefix:], key.ID)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) > MaxCursorBytes {
		return "", errCursor
	}
	return encoded, nil
}

func decodeCursor(value string) (Key, error) {
	if !validText(value, MaxCursorBytes) {
		return Key{}, errCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) <= cursorPrefix {
		return Key{}, errCursor
	}
	nanoseconds := binary.BigEndian.Uint32(raw[8:cursorPrefix])
	id := string(raw[cursorPrefix:])
	if nanoseconds >= uint32(time.Second) || !validText(id, MaxCursorBytes) {
		return Key{}, errCursor
	}
	seconds := int64(binary.BigEndian.Uint64(raw[:8]))
	return Key{ID: id, CreatedAt: time.Unix(seconds, int64(nanoseconds)).UTC()}, nil
}

// ValidCursor accepts an empty optional cursor or one produced by Page.
func ValidCursor(value string) bool {
	if value == "" {
		return true
	}
	_, err := decodeCursor(value)
	return err == nil
}

func validText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
