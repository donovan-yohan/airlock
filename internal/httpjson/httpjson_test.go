package httpjson

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProtocolJSONDoesNotUseHTMLEscaping(t *testing.T) {
	value := map[string]string{"argv": "<&>"}
	encoded, err := Marshal(value)
	if err != nil || bytes.Contains(encoded, []byte(`\u003c`)) {
		t.Fatalf("marshal=%q err=%v", encoded, err)
	}
	response := httptest.NewRecorder()
	Write(response, http.StatusOK, value)
	if response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte(`\u003c`)) {
		t.Fatalf("write status=%d body=%q", response.Code, response.Body.String())
	}
}
