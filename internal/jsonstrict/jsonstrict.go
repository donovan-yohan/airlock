// Package jsonstrict provides the single fail-closed JSON decoder used at
// Airlock's persistence and protocol boundaries.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// maxNestingDepth is deliberately far above Airlock's deepest legitimate
// protocol/state document (currently about five containers) while keeping the
// duplicate-key token walk at constant, small stack depth for hostile input.
const maxNestingDepth = 64

// DecodeOne rejects ambiguous encodings before decoding exactly one value into
// destination. In particular, encoding/json otherwise accepts duplicate object
// keys and replaces malformed Unicode strings with U+FFFD.
func DecodeOne(raw []byte, destination any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	if err := validateSurrogateEscapes(raw); err != nil {
		return err
	}
	if err := validateTokens(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := requireEOF(decoder); err != nil {
		return err
	}
	return nil
}

func validateTokens(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateValue(decoder, 0); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func validateValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case string:
		return nil
	case json.Delim:
		if depth >= maxNestingDepth {
			return errors.New("JSON nesting depth exceeds limit")
		}
		switch value {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = struct{}{}
				if err := validateValue(decoder, depth+1); err != nil {
					return err
				}
			}
			return closeContainer(decoder, '}')
		case '[':
			for decoder.More() {
				if err := validateValue(decoder, depth+1); err != nil {
					return err
				}
			}
			return closeContainer(decoder, ']')
		default:
			return errors.New("unexpected JSON delimiter")
		}
	default:
		return nil
	}
}

func closeContainer(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != expected {
		return errors.New("mismatched JSON delimiter")
	}
	return nil
}

// validateSurrogateEscapes prevents encoding/json from normalizing unpaired
// UTF-16 surrogate escapes to U+FFFD. Literal U+FFFD remains unambiguous and is
// allowed, preserving valid historical text.
func validateSurrogateEscapes(raw []byte) error {
	for index := 0; index < len(raw); index++ {
		if raw[index] != '"' {
			continue
		}
		for index++; index < len(raw) && raw[index] != '"'; index++ {
			if raw[index] != '\\' {
				continue
			}
			index++
			if index >= len(raw) {
				return errors.New("unterminated JSON escape")
			}
			if raw[index] != 'u' {
				continue
			}
			value, ok := hexQuad(raw, index+1)
			if !ok {
				return errors.New("invalid JSON Unicode escape")
			}
			index += 4
			switch {
			case value >= 0xd800 && value <= 0xdbff:
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return errors.New("unpaired JSON high surrogate")
				}
				low, valid := hexQuad(raw, index+3)
				if !valid || low < 0xdc00 || low > 0xdfff {
					return errors.New("unpaired JSON high surrogate")
				}
				index += 6
			case value >= 0xdc00 && value <= 0xdfff:
				return errors.New("unpaired JSON low surrogate")
			}
		}
	}
	return nil
}

func hexQuad(raw []byte, start int) (uint16, bool) {
	if start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, character := range raw[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("JSON must contain exactly one value")
		}
		return err
	}
	return nil
}
