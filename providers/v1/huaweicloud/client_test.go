package huaweicloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func csmsResponse(secretString, secretBinary, versionID string) []byte {
	body, _ := json.Marshal(map[string]any{
		"version": map[string]any{
			"secret_string": secretString,
			"secret_binary": secretBinary,
			"version_metadata": map[string]any{
				"id": versionID,
			},
		},
	})
	return body
}

func TestGetSecret_ReturnsSecretString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("missing Authorization header")
		}
		if r.Header.Get("X-Sdk-Date") == "" {
			t.Error("missing X-Sdk-Date header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(csmsResponse("my-password", "", "v3"))
	}))
	defer srv.Close()

	c := &csmsClient{endpoint: srv.URL, projectID: "proj", ak: "ak", sk: "sk", http: http.DefaultClient}
	val, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
		Key:     "prod/db",
		Version: "latest",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "my-password" {
		t.Errorf("expected 'my-password', got %q", string(val))
	}
}

func TestGetSecret_DecodesSecretBinary(t *testing.T) {
	raw := "binary-data"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(csmsResponse("", encoded, "v1"))
	}))
	defer srv.Close()

	c := &csmsClient{endpoint: srv.URL, projectID: "proj", ak: "ak", sk: "sk", http: http.DefaultClient}
	val, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "cert"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != raw {
		t.Errorf("expected %q, got %q", raw, string(val))
	}
}

func TestGetSecret_ReturnsNoSecretErrorOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &csmsClient{endpoint: srv.URL, projectID: "proj", ak: "ak", sk: "sk", http: http.DefaultClient}
	_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "missing"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var noSecretErr esv1.NoSecretError
	if !errors.As(err, &noSecretErr) {
		t.Fatalf("expected NoSecretError, got %T: %v", err, err)
	}
}

func TestGetSecret_ExtractsJSONProperty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(csmsResponse(`{"password":"hunter2","user":"admin"}`, "", "v1"))
	}))
	defer srv.Close()

	c := &csmsClient{endpoint: srv.URL, projectID: "proj", ak: "ak", sk: "sk", http: http.DefaultClient}
	val, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
		Key:      "prod/db",
		Property: "password",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "hunter2" {
		t.Errorf("expected 'hunter2', got %q", string(val))
	}
}

func TestGetSecret_DefaultsVersionToLatest(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write(csmsResponse("val", "", "v1"))
	}))
	defer srv.Close()

	c := &csmsClient{endpoint: srv.URL, projectID: "proj123", ak: "ak", sk: "sk", http: http.DefaultClient}
	c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "mysecret"})

	expected := "/v1/proj123/secrets/mysecret/versions/latest"
	if capturedPath != expected {
		t.Errorf("expected path %q, got %q", expected, capturedPath)
	}
}

func TestGetSecretMap_ParsesJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(csmsResponse(`{"username":"admin","password":"s3cr3t"}`, "", "v1"))
	}))
	defer srv.Close()

	c := &csmsClient{endpoint: srv.URL, projectID: "proj", ak: "ak", sk: "sk", http: http.DefaultClient}
	m, err := c.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "prod/db"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(m["username"]) != "admin" {
		t.Errorf("expected 'admin', got %q", string(m["username"]))
	}
	if string(m["password"]) != "s3cr3t" {
		t.Errorf("expected 's3cr3t', got %q", string(m["password"]))
	}
}
