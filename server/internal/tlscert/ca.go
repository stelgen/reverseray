// Package tlscert manages the ReverseRay PKI: a self-signed Ed25519 CA
// (pinned by clients) and short-lived leaves (Ed25519 primary, ECDSA P-256
// compat backup), hard-rotated without breaking CA pins.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	leafLifetime = 90 * 24 * time.Hour
	caLifetime   = 10 * 365 * 24 * time.Hour
)

// Bundle is the server PKI material.
type Bundle struct {
	CA      *x509.Certificate
	CAKey   ed25519.PrivateKey
	Leaf    tls.Certificate // Ed25519, served by default
	LeafAlt tls.Certificate // ECDSA P-256, compat profile
	CAPin   string          // base64url(SHA256(SPKI(CA)))
}

// SPKIPin returns the base64url SHA256 of the certificate's SPKI DER.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// LoadOrCreate loads PKI from stateDir or generates it (CA persists,
// leaves reissued when <30d of life left).
func LoadOrCreate(stateDir string, hosts []string) (*Bundle, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	caCert, caKey, err := loadOrCreateCA(stateDir)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	leaf, err := loadOrCreateLeaf(stateDir, caCert, caKey, hosts, "leaf", ed25519Key)
	if err != nil {
		return nil, fmt.Errorf("leaf ed25519: %w", err)
	}
	leafAlt, err := loadOrCreateLeaf(stateDir, caCert, caKey, hosts, "leaf-ecdsa", ecdsaKey)
	if err != nil {
		return nil, fmt.Errorf("leaf ecdsa: %w", err)
	}
	return &Bundle{
		CA:      caCert,
		CAKey:   caKey,
		Leaf:    *leaf,
		LeafAlt: *leafAlt,
		CAPin:   SPKIPin(caCert),
	}, nil
}

type keyKind int

const (
	ed25519Key keyKind = iota
	ecdsaKey
)

func loadOrCreateCA(dir string) (*x509.Certificate, ed25519.PrivateKey, error) {
	certPEM, certErr := os.ReadFile(filepath.Join(dir, "ca.pem"))
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, "ca.key"))
	if certErr == nil && keyErr == nil {
		cert, err := parseCertPEM(certPEM)
		if err != nil {
			return nil, nil, err
		}
		key, err := parseKeyPEM(keyPEM)
		if err != nil {
			return nil, nil, err
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, errors.New("ca key is not ed25519")
		}
		return cert, edKey, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ReverseRay Root CA", Organization: []string{"reverseray"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if err := writePEM(dir, "ca.pem", "CERTIFICATE", der); err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	if err := writePEM(dir, "ca.key", "PRIVATE KEY", kb); err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func loadOrCreateLeaf(dir string, ca *x509.Certificate, caKey ed25519.PrivateKey,
	hosts []string, name string, kind keyKind) (*tls.Certificate, error) {

	certPath := filepath.Join(dir, name+".pem")
	keyPath := filepath.Join(dir, name+".key")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		cert, err := parseCertPEM(certPEM)
		if err == nil {
			key, kerr := parseKeyPEM(keyPEM)
			if kerr == nil && time.Until(cert.NotAfter) > 30*24*time.Hour && cert.CheckSignatureFrom(ca) == nil {
				return &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}, nil
			}
		}
		// Fall through: reissue (rotation without CA change — clients keep working).
	}

	var pub any
	var priv any
	var err error
	if kind == ed25519Key {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		pub, priv, err = p, k, e
	} else {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub, priv, err = &k.PublicKey, k, e
	}
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ReverseRay Server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, pub, caKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := writePEM(dir, name+".pem", "CERTIFICATE", der); err != nil {
		return nil, err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := writePEM(dir, name+".key", "PRIVATE KEY", kb); err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: priv, Leaf: cert}, nil
}

func writePEM(dir, name, typ string, der []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func parseCertPEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func parseKeyPEM(b []byte) (any, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParsePKCS8PrivateKey(blk.Bytes)
}
