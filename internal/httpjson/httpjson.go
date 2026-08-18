package httpjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/donovan-yohan/airlock/internal/jsonstrict"
)

const MaxBodyBytes = 1 << 20

func Decode(w http.ResponseWriter, r *http.Request, destination any) error {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.New("request body exceeds limit or could not be read")
	}
	if err := jsonstrict.DecodeOne(b, destination); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

func Write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = Encode(w, value)
}

// Marshal is the protocol encoding for Airlock JSON bodies. These bodies are
// never embedded as HTML, so escaping '<', '>', and '&' only wastes bounded
// transport/state capacity and makes size accounting deceptive.
func Marshal(value any) ([]byte, error) {
	var encoded bytes.Buffer
	if err := Encode(&encoded, value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

// Encode keeps the standard JSON newline framing while disabling HTML-only
// escaping. Strict readers still reject malformed and duplicate-key input.
func Encode(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func Error(w http.ResponseWriter, status int, message string) {
	Write(w, status, map[string]string{"error": message})
}
