package huaweicloud

import (
	"net/http"
	"strings"
	"testing"
)

func TestSign_AddsXSdkDateHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet,
		"https://csms.example.com/v1/proj/secrets/mysecret/versions/latest", nil)
	req.Header.Set("Content-Type", "application/json")

	sign(req, "myAK", "mySK")

	if req.Header.Get("X-Sdk-Date") == "" {
		t.Fatal("expected X-Sdk-Date header to be set")
	}
}

func TestSign_AddsAuthorizationHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet,
		"https://csms.example.com/v1/proj/secrets/mysecret/versions/latest", nil)
	req.Header.Set("Content-Type", "application/json")

	sign(req, "MYAK123", "MYSK456")

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "SDK-HMAC-SHA256 Access=MYAK123,") {
		t.Fatalf("unexpected Authorization header: %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=") {
		t.Fatalf("missing SignedHeaders in Authorization: %q", auth)
	}
	if !strings.Contains(auth, "Signature=") {
		t.Fatalf("missing Signature in Authorization: %q", auth)
	}
}

func TestSign_SignedHeadersAreSorted(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet,
		"https://csms.example.com/v1/proj/secrets/mysecret/versions/latest", nil)
	req.Header.Set("Content-Type", "application/json")

	sign(req, "ak", "sk")

	auth := req.Header.Get("Authorization")
	var signedHeaders string
	for _, p := range strings.Split(auth, ", ") {
		if strings.HasPrefix(p, "SignedHeaders=") {
			signedHeaders = strings.TrimPrefix(p, "SignedHeaders=")
		}
	}
	if signedHeaders != "content-type;host;x-sdk-date" {
		t.Fatalf("expected 'content-type;host;x-sdk-date', got %q", signedHeaders)
	}
}

func TestSign_DeterministicForFixedTimestamp(t *testing.T) {
	make := func() *http.Request {
		req, _ := http.NewRequest(http.MethodGet,
			"https://csms.example.com/v1/proj/secrets/mysecret/versions/latest", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Sdk-Date", "20240101T120000Z")
		return req
	}
	r1, r2 := make(), make()
	signWithDate(r1, "ak", "sk", "20240101T120000Z")
	signWithDate(r2, "ak", "sk", "20240101T120000Z")

	if r1.Header.Get("Authorization") != r2.Header.Get("Authorization") {
		t.Fatal("expected identical signatures for identical inputs")
	}
}
