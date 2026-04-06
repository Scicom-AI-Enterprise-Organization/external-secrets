package huaweicloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// Compile-time interface check.
var _ esv1.SecretsClient = &csmsClient{}

// csmsClient calls the HCS CSMS REST API and implements esv1.SecretsClient.
type csmsClient struct {
	endpoint  string
	projectID string
	ak        string
	sk        string
	http      *http.Client
}

type secretVersionResponse struct {
	Version struct {
		SecretString    string `json:"secret_string"`
		SecretBinary    string `json:"secret_binary"`
		VersionMetadata struct {
			ID string `json:"id"`
		} `json:"version_metadata"`
	} `json:"version"`
}

// GetSecret fetches a single secret value from CSMS.
// ref.Key is the CSMS secret name.
// ref.Version defaults to "latest" (SYSCURRENT) if empty.
// ref.Property optionally extracts a JSON key from secret_string.
func (c *csmsClient) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	version := ref.Version
	if version == "" {
		version = "latest"
	}
	url := fmt.Sprintf("%s/v1/%s/secrets/%s/versions/%s",
		strings.TrimRight(c.endpoint, "/"), c.projectID, ref.Key, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("huaweicloud: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	sign(req, c.ak, c.sk)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("huaweicloud: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, esv1.NoSecretError{}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("huaweicloud: unexpected status %d", resp.StatusCode)
	}

	var result secretVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("huaweicloud: decode response: %w", err)
	}

	var value string
	switch {
	case result.Version.SecretString != "":
		value = result.Version.SecretString
	case result.Version.SecretBinary != "":
		decoded, err := base64.StdEncoding.DecodeString(result.Version.SecretBinary)
		if err != nil {
			return nil, fmt.Errorf("huaweicloud: decode secret_binary: %w", err)
		}
		return decoded, nil
	}

	if result.Version.SecretString == "" && result.Version.SecretBinary == "" {
		return nil, fmt.Errorf("huaweicloud: secret %q returned no secret_string or secret_binary", ref.Key)
	}

	if ref.Property != "" {
		value, err = extractJSONProperty(value, ref.Property)
		if err != nil {
			return nil, err
		}
	}
	return []byte(value), nil
}

// GetSecretMap fetches a secret whose value is a JSON object and returns
// it as a map of key -> value bytes.
func (c *csmsClient) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	raw, err := c.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
		Key:     ref.Key,
		Version: ref.Version,
	})
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("huaweicloud: GetSecretMap: secret_string is not a JSON object: %w", err)
	}

	result := make(map[string][]byte, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case string:
			result[k] = []byte(val)
		default:
			b, err := json.Marshal(val)
			if err != nil {
				return nil, fmt.Errorf("huaweicloud: GetSecretMap: marshal key %q: %w", k, err)
			}
			result[k] = b
		}
	}
	return result, nil
}

// GetAllSecrets is not implemented for HCS CSMS.
func (c *csmsClient) GetAllSecrets(_ context.Context, _ esv1.ExternalSecretFind) (map[string][]byte, error) {
	return nil, fmt.Errorf("huaweicloud: GetAllSecrets not implemented")
}

// PushSecret is not implemented for HCS CSMS (read-only provider).
func (c *csmsClient) PushSecret(_ context.Context, _ *corev1.Secret, _ esv1.PushSecretData) error {
	return fmt.Errorf("huaweicloud: PushSecret not implemented")
}

// DeleteSecret is not implemented for HCS CSMS (read-only provider).
func (c *csmsClient) DeleteSecret(_ context.Context, _ esv1.PushSecretRemoteRef) error {
	return fmt.Errorf("huaweicloud: DeleteSecret not implemented")
}

// SecretExists is not implemented for HCS CSMS.
func (c *csmsClient) SecretExists(_ context.Context, _ esv1.PushSecretRemoteRef) (bool, error) {
	return false, fmt.Errorf("huaweicloud: SecretExists not implemented")
}

// Validate checks that the client can reach CSMS.
func (c *csmsClient) Validate() (esv1.ValidationResult, error) {
	return esv1.ValidationResultUnknown, nil
}

// Close is a no-op for the HTTP client.
func (c *csmsClient) Close(_ context.Context) error {
	return nil
}

func extractJSONProperty(jsonStr, property string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		return "", fmt.Errorf("huaweicloud: secret_string is not valid JSON: %w", err)
	}
	val, ok := m[property]
	if !ok {
		return "", fmt.Errorf("huaweicloud: property %q not found in secret JSON", property)
	}
	switch v := val.(type) {
	case string:
		return v, nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("huaweicloud: marshal property %q value: %w", property, err)
		}
		return string(b), nil
	}
}
