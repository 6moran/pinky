package traffic

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The certificate authority's files, in the folder LoadCA keeps them in
// (Pinky's data folder). The key is readable by the person's user only.
const (
	CACertFile = "traffic-ca.crt"
	CAKeyFile  = "traffic-ca.key"
)

// How long certificates last. iOS refuses server certificates valid for
// more than 825 days; a year stays well inside every platform's limit.
const (
	caLife   = 5 * 365 * 24 * time.Hour
	leafLife = 365 * 24 * time.Hour
	// leafKeep bounds the certificates kept for hosts; the cache starts
	// over past it.
	leafKeep = 1024
)

// CA is the certificate authority Pinky makes for this computer, which
// signs a certificate for each host the proxy decrypts. Phones decrypt
// only once the person installs and trusts its certificate.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
	der  []byte

	mu      sync.Mutex
	leafKey *ecdsa.PrivateKey
	leaves  map[string]*tls.Certificate
}

// NewCA makes a new certificate authority, in memory.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	// The name carries a few random letters, so two computers' authorities
	// can be told apart in the phone's list of certificates.
	tag := fmt.Sprintf("%06X", new(big.Int).And(serial, big.NewInt(0xFFFFFF)).Int64())
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Pinky Traffic CA " + tag, Organization: []string{"Pinky"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLife),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return newCA(der, key)
}

func newCA(der []byte, key crypto.Signer) (*CA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("traffic: the certificate is not a certificate authority")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, der: der, leafKey: leafKey, leaves: map[string]*tls.Certificate{}}, nil
}

// LoadCA reads the certificate authority from dir, or makes one and saves
// it there when there is none (or it has expired): the certificate as
// CACertFile, the key as CAKeyFile, readable by this user only. A new one
// has to be installed on the phones again.
func LoadCA(dir string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile)
	if ca, err := readCA(certPath, keyPath); err == nil && time.Now().Before(ca.cert.NotAfter.Add(-24*time.Hour)) {
		return ca, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("traffic: read the certificate authority: %w", err)
	}
	ca, err := NewCA()
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := writeFile(certPath, ca.CertPEM(), 0o600); err != nil {
		return nil, err
	}
	return ca, nil
}

func readCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("the key cannot sign")
	}
	return newCA(cb.Bytes, signer)
}

// writeFile writes a file through a temporary one, with perm from the
// start.
func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// CertDER returns the authority's certificate, DER-encoded, as phones
// install it.
func (c *CA) CertDER() []byte { return c.der }

// CertPEM returns the authority's certificate, PEM-encoded.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// Name returns the authority's name, as phones list it.
func (c *CA) Name() string { return c.cert.Subject.CommonName }

// Fingerprint returns the certificate's SHA-256 fingerprint, as phones
// show it: "AB:CD:…".
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// Pool returns a pool that trusts the authority, for tests and checks.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// Leaf returns a certificate for host, signed by the authority.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("traffic: no host to make a certificate for")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.leaves[host]; ok && time.Now().Before(l.Leaf.NotAfter) {
		return l, nil
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, c.leafKey.Public(), c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	out := &tls.Certificate{Certificate: [][]byte{der, c.der}, PrivateKey: c.leafKey, Leaf: leaf}
	if len(c.leaves) >= leafKeep {
		c.leaves = map[string]*tls.Certificate{}
	}
	c.leaves[host] = out
	return out, nil
}

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}
