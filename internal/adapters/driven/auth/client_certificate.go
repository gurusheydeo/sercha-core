package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 used only for the x5t thumbprint per RFC 7515, not for security hashing
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"time"
)

// ClientCertificateCredential implements ClientCredential using a signed JWT
// client assertion (RFC 7521 §4.2). The assertion is signed with an RSA
// private key; the corresponding certificate is identified by its SHA-1
// thumbprint in the JWT header (x5t), as required by providers such as
// Microsoft Entra ID.
type ClientCertificateCredential struct {
	// PrivateKey is the RSA private key used to sign the client assertion JWT.
	PrivateKey *rsa.PrivateKey

	// Thumbprint is the SHA-1 fingerprint of the DER-encoded certificate.
	// It is base64url-encoded into the "x5t" JWT header field.
	Thumbprint []byte

	// Audience is the token endpoint URL (the "aud" claim in the assertion).
	Audience string

	// Issuer is typically the OAuth client ID (both "iss" and "sub" claims).
	Issuer string
}

// Apply builds a signed JWT client assertion and sets client_assertion and
// client_assertion_type on the supplied form.
func (c *ClientCertificateCredential) Apply(form url.Values) error {
	assertion, err := c.buildAssertion()
	if err != nil {
		return fmt.Errorf("build client assertion: %w", err)
	}
	form.Set("client_assertion", assertion)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	return nil
}

// jwtHeader is the JOSE header for the client assertion.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	X5T string `json:"x5t"` // base64url(SHA-1 thumbprint)
}

// jwtClaims is the payload for the client assertion.
type assertionClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

// buildAssertion creates and signs the JWT client assertion.
func (c *ClientCertificateCredential) buildAssertion() (string, error) {
	now := time.Now()

	// Generate a random jti to prevent assertion replay.
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiBytes)

	hdr := jwtHeader{
		Alg: "RS256",
		Typ: "JWT",
		X5T: base64.RawURLEncoding.EncodeToString(c.Thumbprint),
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}

	claims := assertionClaims{
		Iss: c.Issuer,
		Sub: c.Issuer,
		Aud: c.Audience,
		Exp: now.Add(5 * time.Minute).Unix(),
		Nbf: now.Unix(),
		Iat: now.Unix(),
		Jti: jti,
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}

	header := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// LoadClientCertificate parses PEM-encoded certificate and private key bytes
// and returns a ClientCertificateCredential ready for use with
// ClientCredentialsTokenProvider.
//
// pemBytes must contain at least one CERTIFICATE block.
// keyPEMBytes must contain exactly one RSA PRIVATE KEY or PKCS8 PRIVATE KEY block.
func LoadClientCertificate(pemBytes, keyPEMBytes []byte, audience, issuer string) (*ClientCertificateCredential, error) {
	// Parse certificate to compute thumbprint.
	certBlock, _ := pem.Decode(pemBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE block found in cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	// SHA-1 thumbprint of DER bytes (x5t header value per RFC 7517).
	//nolint:gosec // SHA-1 required by the x5t specification; not used for security
	thumbprint := sha1.Sum(cert.Raw)

	// Parse private key.
	keyBlock, _ := pem.Decode(keyPEMBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block found in key bytes")
	}

	var privateKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key: %w", err)
		}
	case "PRIVATE KEY":
		key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse PKCS8 private key: %w", err2)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported key PEM block type: %s", keyBlock.Type)
	}

	return &ClientCertificateCredential{
		PrivateKey: privateKey,
		Thumbprint: thumbprint[:],
		Audience:   audience,
		Issuer:     issuer,
	}, nil
}
