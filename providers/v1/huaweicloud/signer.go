package huaweicloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	signingAlgorithm = "SDK-HMAC-SHA256"
	sdkDateFormat    = "20060102T150405Z"
)

// sign adds X-Sdk-Date and Authorization headers to req using Huawei AK/SK signing.
func sign(req *http.Request, ak, sk string) {
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	ts := time.Now().UTC().Format(sdkDateFormat)
	signWithDate(req, ak, sk, ts)
}

// signWithDate signs req using the provided timestamp. Used in tests.
func signWithDate(req *http.Request, ak, sk, ts string) {
	req.Header.Set("X-Sdk-Date", ts)

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	signedHeaderNames := []string{"content-type", "host", "x-sdk-date"}
	headerValues := map[string]string{
		"content-type": strings.TrimSpace(req.Header.Get("Content-Type")),
		"host":         host,
		"x-sdk-date":   ts,
	}

	var canonHeaders strings.Builder
	for _, k := range signedHeaderNames {
		canonHeaders.WriteString(k + ":" + headerValues[k] + "\n")
	}
	signedHeaders := strings.Join(signedHeaderNames, ";")

	canonURI := req.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}
	// APIG normalizes paths by appending a trailing slash before verifying
	// the signature. Match that behaviour so signatures are accepted.
	if !strings.HasSuffix(canonURI, "/") {
		canonURI += "/"
	}

	canonRequest := strings.Join([]string{
		req.Method,
		canonURI,
		buildCanonicalQuery(req),
		canonHeaders.String(),
		signedHeaders,
		// Body signing is not required for CSMS GET requests; always use the empty-string hash.
		hexSHA256([]byte("")),
	}, "\n")

	stringToSign := strings.Join([]string{
		signingAlgorithm,
		ts,
		hexSHA256([]byte(canonRequest)),
	}, "\n")

	sig := hexHMACSHA256([]byte(sk), []byte(stringToSign))
	req.Header.Set("Authorization", fmt.Sprintf(
		"%s Access=%s, SignedHeaders=%s, Signature=%s",
		signingAlgorithm, ak, signedHeaders, sig,
	))
}

func buildCanonicalQuery(req *http.Request) string {
	q := req.URL.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hexHMACSHA256(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
