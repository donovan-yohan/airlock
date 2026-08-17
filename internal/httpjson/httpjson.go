package httpjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
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
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid JSON body")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("body must contain one JSON object")
	}
	return nil
}

func Write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func Error(w http.ResponseWriter, status int, message string) {
	Write(w, status, map[string]string{"error": message})
}
