package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"caforge/internal/domain"
)

func TestEncryptedPKCS8RoundTrip(t *testing.T) {
	key, err := GenerateKey(domain.ECDSAP256, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalPrivateKey(key, []byte("correct horse battery staple"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("unexpected PEM: %q", encoded)
	}
	parsed, err := ParsePrivateKey(encoded, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("got %T", parsed)
	}
	if _, err = ParsePrivateKey(encoded, []byte("wrong")); err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestGenerateRSAAndECDSA(t *testing.T) {
	for _, alg := range []domain.Algorithm{domain.ECDSAP384, domain.RSA3072} {
		key, err := GenerateKey(alg, rand.Reader)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		pub, err := PublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := AlgorithmOfPublicKey(pub)
		if err != nil || got != alg {
			t.Fatalf("%s became %s: %v", alg, got, err)
		}
	}
}

func TestLeafProfilesAndValidityBoundary(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	issuerExpiry := now.Add(48 * time.Hour)
	server, err := LeafTemplate(domain.IssueRequest{CommonName: "web", Profile: domain.Server, DNSNames: []string{"example.test"}, IPAddresses: []string{"127.0.0.1"}, Days: 397}, big.NewInt(1), now, issuerExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if !server.NotAfter.Equal(issuerExpiry) {
		t.Fatalf("validity not capped: %v", server.NotAfter)
	}
	if len(server.ExtKeyUsage) != 1 || server.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("server EKU missing")
	}
	if !server.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatal("IP SAN missing")
	}
	client, err := LeafTemplate(domain.IssueRequest{CommonName: "user", Profile: domain.Client, Days: 10}, big.NewInt(2), now, now.AddDate(1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if client.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("client EKU missing")
	}
	if _, err = LeafTemplate(domain.IssueRequest{CommonName: "bad", Profile: domain.Server, Days: 1}, big.NewInt(3), now, now.AddDate(1, 0, 0)); err == nil {
		t.Fatal("server without SAN accepted")
	}
	if _, err = LeafTemplate(domain.IssueRequest{CommonName: "bad", Profile: domain.Server, DNSNames: []string{"bad name"}, Days: 1}, big.NewInt(4), now, now.AddDate(1, 0, 0)); err == nil {
		t.Fatal("invalid DNS SAN accepted")
	}
}

func TestCSRValidation(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr.test"}, DNSNames: []string{"csr.test"}, ExtraExtensions: []pkix.Extension{{Id: []int{2, 5, 29, 19}, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseAndValidateCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), domain.Server)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "csr.test" {
		t.Fatal("wrong CSR")
	}
	der, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "no-san"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseAndValidateCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), domain.Server); err == nil {
		t.Fatal("server CSR without SAN accepted")
	}
}
