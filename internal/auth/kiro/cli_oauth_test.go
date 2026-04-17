package kiro

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildKiroCLISignInURLExact(t *testing.T) {
	state := "AbC123xyZ9"
	challenge := "pkce_challenge_value"
	got := buildKiroCLISignInURL(state, challenge)
	want := "https://app.kiro.dev/signin?state=AbC123xyZ9&code_challenge=pkce_challenge_value&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A3128&redirect_from=kirocli"
	if got != want {
		t.Fatalf("signin URL mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestGenerateKiroCLIStateShape(t *testing.T) {
	state, err := generateKiroCLIState()
	if err != nil {
		t.Fatalf("generateKiroCLIState failed: %v", err)
	}
	if len(state) != 10 {
		t.Fatalf("state length mismatch: got %d want 10", len(state))
	}
	for _, ch := range state {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') {
			t.Fatalf("state has non-alnum character: %q", ch)
		}
	}
}

func TestGenerateKiroCLIPKCEShape(t *testing.T) {
	verifier, challenge, err := generateKiroCLIPKCE()
	if err != nil {
		t.Fatalf("generateKiroCLIPKCE failed: %v", err)
	}
	if verifier == "" || challenge == "" {
		t.Fatalf("verifier/challenge must be non-empty")
	}
	if strings.ContainsAny(verifier, "+/=") {
		t.Fatalf("verifier not base64url raw: %s", verifier)
	}
	if strings.ContainsAny(challenge, "+/=") {
		t.Fatalf("challenge not base64url raw: %s", challenge)
	}
	h := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	if challenge != wantChallenge {
		t.Fatalf("challenge mismatch with verifier: got %s want %s", challenge, wantChallenge)
	}
}

func TestSignTelemetryRequestHeaderShape(t *testing.T) {
	o := &KiroCLIOAuth{}
	body := []byte(`{"x":1}`)
	creds := &telemetryTemporaryCredentials{
		AccessKeyID:  "ASIAEXAMPLE",
		SecretKey:    "secret",
		SessionToken: "session-token",
	}
	now := time.Date(2026, 4, 17, 11, 49, 2, 0, time.UTC)
	req := httptest.NewRequest(http.MethodPost, kiroCLITelemetryEndpoint, strings.NewReader(string(body)))

	o.signTelemetryRequest(req, body, creds, now)

	if got := req.Header.Get("User-Agent"); got != kiroCLIRustUserAgent {
		t.Fatalf("unexpected User-Agent: %s", got)
	}
	if got := req.Header.Get("X-Amz-User-Agent"); got != kiroCLITelemetryAmzUA {
		t.Fatalf("unexpected X-Amz-User-Agent: %s", got)
	}
	if got := req.Header.Get("X-Amz-Date"); got == "" {
		t.Fatalf("missing X-Amz-Date")
	}
	if got := req.Header.Get("Authorization"); !strings.Contains(got, "AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/") {
		t.Fatalf("invalid Authorization header: %s", got)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "session-token" {
		t.Fatalf("unexpected security token: %s", got)
	}
}

func TestNormalizeTelemetryOS(t *testing.T) {
	if got := normalizeTelemetryOS("darwin"); got != "macos" {
		t.Fatalf("darwin mapping mismatch: %s", got)
	}
	if got := normalizeTelemetryOS("linux"); got != "linux" {
		t.Fatalf("linux mapping mismatch: %s", got)
	}
	if got := normalizeTelemetryOS("windows"); got != "windows" {
		t.Fatalf("windows mapping mismatch: %s", got)
	}
}
