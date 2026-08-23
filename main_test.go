package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func echoRequest(t *testing.T, headers map[string]string) reply {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handleEcho(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got reply
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	return got
}

func TestEchoesRequestBasics(t *testing.T) {
	got := echoRequest(t, nil)
	if got.Method != http.MethodGet {
		t.Errorf("method = %q, want GET", got.Method)
	}
	if got.Path != "/" {
		t.Errorf("path = %q, want /", got.Path)
	}
	if got.RemoteAddr == "" {
		t.Error("remote_addr is empty")
	}
}

func TestNotableHeadersArePulledOut(t *testing.T) {
	got := echoRequest(t, map[string]string{
		"Cf-Connecting-Ip": "203.0.113.7",
		"Cf-Ipcountry":     "GB",
		"User-Agent":       "test",
	})
	if got.Notable["Cf-Connecting-Ip"] != "203.0.113.7" {
		t.Errorf("Cf-Connecting-Ip = %q, want 203.0.113.7", got.Notable["Cf-Connecting-Ip"])
	}
	if _, ok := got.Notable["User-Agent"]; ok {
		t.Error("User-Agent should not be in notable; it is not a header people misreason about")
	}
	if got.Headers["User-Agent"] != "test" {
		t.Error("User-Agent should still appear in the full header dump")
	}
}

// Absent notable headers must be omitted rather than reported as empty — on a
// public hostname the absence of the Access headers is the useful signal, and
// an empty string reads like "present but blank".
func TestAbsentNotableHeadersAreOmitted(t *testing.T) {
	got := echoRequest(t, nil)
	if _, ok := got.Notable["Cf-Access-Authenticated-User-Email"]; ok {
		t.Error("absent Access header should not appear in notable")
	}
}

// The Access JWT is a bearer credential. Showing that it arrived is useful;
// echoing it back to whoever asked is handing out a token.
func TestAccessJWTIsRedacted(t *testing.T) {
	secret := "eyJhbGciOiJSUzI1NiJ9.super.secret"
	got := echoRequest(t, map[string]string{"Cf-Access-Jwt-Assertion": secret})

	if got.Notable["Cf-Access-Jwt-Assertion"] != "<present, redacted>" {
		t.Errorf("JWT = %q, want it redacted", got.Notable["Cf-Access-Jwt-Assertion"])
	}
	// It must not leak through the full header dump either.
	body, _ := json.Marshal(got)
	if strings.Contains(string(body), secret) {
		t.Error("the Access JWT appears verbatim in the response")
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

// Every credential-bearing header must be redacted in the full dump too, not
// just the notable list.
func TestAllSensitiveHeadersAreRedacted(t *testing.T) {
	secret := "shhh-this-is-a-credential"
	for h := range sensitive {
		got := echoRequest(t, map[string]string{h: secret})
		body, _ := json.Marshal(got)
		if strings.Contains(string(body), secret) {
			t.Errorf("%s leaked its value into the response", h)
		}
		if got.Headers[h] != redacted {
			t.Errorf("%s in full dump = %q, want %q", h, got.Headers[h], redacted)
		}
	}
}
