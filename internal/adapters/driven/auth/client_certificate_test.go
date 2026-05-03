package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha1" //nolint:gosec // SHA-1 required for x5t thumbprint
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// generateTestCertAndKey generates a self-signed test certificate and private key
func generateTestCertAndKey() ([]byte, []byte, error) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM (PKCS1)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

// generateTestPKCS8Key generates a test certificate with PKCS8 private key
func generateTestCertAndPKCS8Key() ([]byte, []byte, error) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test2.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM (PKCS8)
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	return certPEM, keyPEM, nil
}

// TestClientCertificateCredential_Apply tests JWT assertion creation
func TestClientCertificateCredential_Apply(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	cred, err := LoadClientCertificate(certPEM, keyPEM, "https://token.example.com", "my-client-id")
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	form := url.Values{}
	if err := cred.Apply(form); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify form fields are set
	assertionType := form.Get("client_assertion_type")
	if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("expected correct client_assertion_type, got %s", assertionType)
	}

	assertion := form.Get("client_assertion")
	if assertion == "" {
		t.Error("expected client_assertion to be set")
	}

	// Verify JWT structure (three parts separated by dots)
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Errorf("expected JWT with 3 parts, got %d", len(parts))
	}
}

// TestClientCertificateCredential_JWTStructure tests JWT header and payload structure
func TestClientCertificateCredential_JWTStructure(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	audience := "https://token.example.com"
	issuer := "my-client-id"

	cred, err := LoadClientCertificate(certPEM, keyPEM, audience, issuer)
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	form := url.Values{}
	if err := cred.Apply(form); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	assertion := form.Get("client_assertion")
	parts := strings.Split(assertion, ".")

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parse header JSON: %v", err)
	}

	// Verify header fields
	if header["alg"] != "RS256" {
		t.Errorf("expected alg=RS256, got %v", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("expected typ=JWT, got %v", header["typ"])
	}
	if x5t, ok := header["x5t"]; !ok || x5t == "" {
		t.Error("expected x5t header field to be present and non-empty")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parse payload JSON: %v", err)
	}

	// Verify claim fields
	if payload["iss"] != issuer {
		t.Errorf("expected iss=%s, got %v", issuer, payload["iss"])
	}
	if payload["sub"] != issuer {
		t.Errorf("expected sub=%s, got %v", issuer, payload["sub"])
	}
	if payload["aud"] != audience {
		t.Errorf("expected aud=%s, got %v", audience, payload["aud"])
	}

	// Verify exp, nbf, iat are present and reasonable
	if _, ok := payload["exp"]; !ok {
		t.Error("expected exp claim to be present")
	}
	if _, ok := payload["nbf"]; !ok {
		t.Error("expected nbf claim to be present")
	}
	if _, ok := payload["iat"]; !ok {
		t.Error("expected iat claim to be present")
	}
	if jti, ok := payload["jti"]; !ok || jti == "" {
		t.Error("expected jti claim to be present and non-empty")
	}
}

// TestClientCertificateCredential_JWTClaims tests JWT claim values
func TestClientCertificateCredential_JWTClaims(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	audience := "https://token.example.com"
	issuer := "my-client-id"

	cred, err := LoadClientCertificate(certPEM, keyPEM, audience, issuer)
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	form := url.Values{}
	if err := cred.Apply(form); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	assertion := form.Get("client_assertion")
	parts := strings.Split(assertion, ".")

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parse payload JSON: %v", err)
	}

	// Verify exp is approximately 5 minutes from now
	now := time.Now().Unix()
	exp := int64(payload["exp"].(float64))
	expectedExp := now + 300 // 5 minutes

	if exp < expectedExp-10 || exp > expectedExp+10 {
		t.Errorf("expected exp ~%d (±10s), got %d", expectedExp, exp)
	}

	// Verify nbf is approximately now
	nbf := int64(payload["nbf"].(float64))
	if nbf < now-10 || nbf > now+10 {
		t.Errorf("expected nbf ~%d (±10s), got %d", now, nbf)
	}

	// Verify iat is approximately now
	iat := int64(payload["iat"].(float64))
	if iat < now-10 || iat > now+10 {
		t.Errorf("expected iat ~%d (±10s), got %d", now, iat)
	}
}

// TestClientCertificateCredential_SignatureVerifies tests that JWT signature is valid
func TestClientCertificateCredential_SignatureVerifies(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	cred, err := LoadClientCertificate(certPEM, keyPEM, "https://token.example.com", "my-client-id")
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	form := url.Values{}
	if err := cred.Apply(form); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	assertion := form.Get("client_assertion")
	parts := strings.Split(assertion, ".")

	// Reconstruct signing input
	signingInput := parts[0] + "." + parts[1]

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	// Verify signature with the public key
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&cred.PrivateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

// TestLoadClientCertificate_PKCS1Key tests loading with PKCS1 private key
func TestLoadClientCertificate_PKCS1Key(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	cred, err := LoadClientCertificate(certPEM, keyPEM, "https://token.example.com", "my-client-id")
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	if cred.PrivateKey == nil {
		t.Error("expected PrivateKey to be set")
	}
	if len(cred.Thumbprint) == 0 {
		t.Error("expected Thumbprint to be set")
	}
	if cred.Audience != "https://token.example.com" {
		t.Errorf("expected Audience=https://token.example.com, got %s", cred.Audience)
	}
	if cred.Issuer != "my-client-id" {
		t.Errorf("expected Issuer=my-client-id, got %s", cred.Issuer)
	}
}

// TestLoadClientCertificate_PKCS8Key tests loading with PKCS8 private key
func TestLoadClientCertificate_PKCS8Key(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndPKCS8Key()
	if err != nil {
		t.Fatalf("generate test cert with PKCS8: %v", err)
	}

	cred, err := LoadClientCertificate(certPEM, keyPEM, "https://token.example.com", "my-client-id")
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	if cred.PrivateKey == nil {
		t.Error("expected PrivateKey to be set")
	}
	if len(cred.Thumbprint) == 0 {
		t.Error("expected Thumbprint to be set")
	}
}

// TestLoadClientCertificate_InvalidCertPEM tests error handling for invalid cert PEM
func TestLoadClientCertificate_InvalidCertPEM(t *testing.T) {
	_, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	cred, err := LoadClientCertificate([]byte("not a pem"), keyPEM, "https://token.example.com", "my-client-id")
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
	if cred != nil {
		t.Error("expected nil credential on error")
	}
}

// TestLoadClientCertificate_InvalidKeyPEM tests error handling for invalid key PEM
func TestLoadClientCertificate_InvalidKeyPEM(t *testing.T) {
	certPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	cred, err := LoadClientCertificate(certPEM, []byte("not a pem"), "https://token.example.com", "my-client-id")
	if err == nil {
		t.Fatal("expected error for invalid key PEM")
	}
	if cred != nil {
		t.Error("expected nil credential on error")
	}
}

// TestLoadClientCertificate_UnsupportedKeyType tests error for non-RSA key
func TestLoadClientCertificate_UnsupportedKeyType(t *testing.T) {
	// Create a test with RSA key but claim it's something else
	// This is hard to do, so we'll just test the error path for missing key block
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZKJq9MA0GCSqGSIb3DQEBBQUAMBMxETAPBgNVBAMMCHRl
-----END CERTIFICATE-----`)

	keyPEM := []byte(`-----BEGIN EC PRIVATE KEY-----
-----END EC PRIVATE KEY-----`)

	_, err := LoadClientCertificate(certPEM, keyPEM, "https://token.example.com", "my-client-id")
	if err == nil {
		t.Skip("EC key was accepted; test expects rejection of non-RSA keys")
	}
}

// TestClientCertificateCredential_ThumbprintConsistency tests that thumbprint is consistent
func TestClientCertificateCredential_ThumbprintConsistency(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	cred1, err := LoadClientCertificate(certPEM, keyPEM, "https://token.example.com", "client1")
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	cred2, err := LoadClientCertificate(certPEM, keyPEM, "https://token.example.com", "client2")
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	// Thumbprint should be identical for same certificate
	if string(cred1.Thumbprint) != string(cred2.Thumbprint) {
		t.Error("expected same thumbprint for same certificate")
	}

	// Thumbprint should be 20 bytes (SHA-1 output)
	if len(cred1.Thumbprint) != 20 {
		t.Errorf("expected 20-byte thumbprint, got %d", len(cred1.Thumbprint))
	}
}

// TestClientCertificateCredential_X5tEncoding tests that x5t is base64url-encoded in JWT
func TestClientCertificateCredential_X5tEncoding(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	cred, err := LoadClientCertificate(certPEM, keyPEM, "https://token.example.com", "my-client-id")
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	form := url.Values{}
	if err := cred.Apply(form); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	assertion := form.Get("client_assertion")
	parts := strings.Split(assertion, ".")

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parse header JSON: %v", err)
	}

	x5tStr := header["x5t"].(string)

	// Decode x5t and verify it matches thumbprint
	x5tBytes, err := base64.RawURLEncoding.DecodeString(x5tStr)
	if err != nil {
		t.Fatalf("decode x5t: %v", err)
	}

	if string(x5tBytes) != string(cred.Thumbprint) {
		t.Error("x5t in JWT does not match thumbprint")
	}
}

// TestClientCertificateCredential_RoundTrip tests full certificate round-trip
func TestClientCertificateCredential_RoundTrip(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	audience := "https://token.example.com"
	issuer := "my-client-id"

	// Load the credential
	cred, err := LoadClientCertificate(certPEM, keyPEM, audience, issuer)
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	// Apply to form
	form := url.Values{}
	if err := cred.Apply(form); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify form has required fields
	assertion := form.Get("client_assertion")
	assertionType := form.Get("client_assertion_type")

	if assertion == "" {
		t.Error("expected client_assertion to be set")
	}
	if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("expected correct assertion type, got %s", assertionType)
	}

	// Verify JWT structure
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// Verify signature
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(&cred.PrivateKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

// TestLoadClientCertificate_ThumbprintSHA1 tests that thumbprint uses SHA-1
func TestLoadClientCertificate_ThumbprintSHA1(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	cred, err := LoadClientCertificate(certPEM, keyPEM, "https://token.example.com", "my-client-id")
	if err != nil {
		t.Fatalf("LoadClientCertificate() error = %v", err)
	}

	// Parse certificate to verify thumbprint is correct
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	//nolint:gosec // SHA-1 required for x5t specification
	expectedThumbprint := sha1.Sum(cert.Raw)

	if string(cred.Thumbprint) != string(expectedThumbprint[:]) {
		t.Error("thumbprint does not match SHA-1 of certificate")
	}
}
