package certificate_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"caforge/internal/authority"
	"caforge/internal/certificate"
	"caforge/internal/domain"
	"caforge/internal/pki"
	"caforge/internal/revocation"
	"caforge/internal/store"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestEndToEndAndOpenSSLCompatibility(t *testing.T) {
	rootDir := t.TempDir()
	repo, err := store.New(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Init(); err != nil {
		t.Fatal(err)
	}
	authorities := authority.New(repo)
	certs := certificate.New(repo, authorities)
	revocations := revocation.New(repo)
	rootPW := []byte("root passphrase")
	intPW := []byte("intermediate passphrase")
	root, err := authorities.CreateRoot(authority.CreateRootRequest{Name: "Test Root", Algorithm: domain.ECDSAP384, Days: 3650, MaxPathLen: 1, Password: rootPW})
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := authorities.CreateIntermediate(authority.CreateIntermediateRequest{ParentID: root.ID, Name: "Issuing CA", Algorithm: domain.ECDSAP384, Days: 1825, ParentPassword: rootPW, Password: intPW})
	if err != nil {
		t.Fatal(err)
	}
	server, err := certs.Issue(domain.IssueRequest{CAID: intermediate.ID, CommonName: "server.test", Profile: domain.Server, Algorithm: domain.ECDSAP256, DNSNames: []string{"server.test"}, IPAddresses: []string{"127.0.0.1"}, Days: 397, EncryptKey: false}, intPW)
	if err != nil {
		t.Fatal(err)
	}
	client, err := certs.Issue(domain.IssueRequest{CAID: intermediate.ID, CommonName: "client", Profile: domain.Client, Algorithm: domain.ECDSAP256, Days: 397, EncryptKey: false}, intPW)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := certs.Renew(intermediate.ID, client.Serial, 397, intPW, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Serial == client.Serial || renewed.RenewedFrom != client.Serial {
		t.Fatalf("bad renewal: %#v", renewed)
	}
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr.test"}, DNSNames: []string{"csr.test"}}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csrCert, err := certs.SignCSR(domain.CSRRequest{CAID: intermediate.ID, Profile: domain.Server, CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), Days: 30}, intPW)
	if err != nil {
		t.Fatal(err)
	}
	if csrCert.HasKey {
		t.Fatal("CSR certificate unexpectedly owns key")
	}
	if err = revocations.Revoke(intermediate.ID, server.Serial, domain.KeyCompromise, intPW); err != nil {
		t.Fatal(err)
	}
	_, _, status, err := certs.Get(intermediate.ID, server.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if status != 'R' {
		t.Fatalf("status %c", status)
	}
	crl, err := revocations.Read(intermediate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].ReasonCode != int(domain.KeyCompromise) {
		t.Fatalf("bad CRL: %#v", crl.RevokedCertificateEntries)
	}
	pfx, err := certs.Export(intermediate.ID, client.Serial, domain.ExportPKCS12, nil, []byte("export pass"))
	if err != nil {
		t.Fatal(err)
	}
	_, p12cert, caCerts, err := pkcs12.DecodeChain(pfx, "export pass")
	if err != nil {
		t.Fatal(err)
	}
	if p12cert.Subject.CommonName != "client" || len(caCerts) != 2 {
		t.Fatalf("bad PKCS#12 chain: %s, %d", p12cert.Subject.CommonName, len(caCerts))
	}
	rootPEM, _ := repo.ReadCACertificate(root.ID)
	rootCert, err := pki.ParseCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	intPEM, _ := repo.ReadCACertificate(intermediate.ID)
	intCert, err := pki.ParseCertificate(intPEM)
	if err != nil {
		t.Fatal(err)
	}
	_, leaf, _, err := certs.Get(intermediate.ID, server.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if err = intCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatal(err)
	}
	if err = leaf.CheckSignatureFrom(intCert); err != nil {
		t.Fatal(err)
	}
	if openssl, lookErr := exec.LookPath("openssl"); lookErr == nil {
		leafPath := filepath.Join(rootDir, "cas", intermediate.ID, "issued", server.Serial, "cert.pem")
		clientPath := filepath.Join(rootDir, "cas", intermediate.ID, "issued", client.Serial, "cert.pem")
		intPath := filepath.Join(rootDir, "cas", intermediate.ID, "certs", "ca.cert.pem")
		rootPath := filepath.Join(rootDir, "cas", root.ID, "certs", "ca.cert.pem")
		rootKeyPath := filepath.Join(rootDir, "cas", root.ID, "private", "ca.key.pem")
		cmd := exec.Command(openssl, "pkey", "-in", rootKeyPath, "-passin", "pass:"+string(rootPW), "-noout")
		if output, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("openssl encrypted PKCS#8: %v\n%s", e, output)
		}
		cmd = exec.Command(openssl, "verify", "-CAfile", rootPath, "-untrusted", intPath, leafPath)
		if output, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("openssl verify: %v\n%s", e, output)
		}
		crlPath := filepath.Join(rootDir, "cas", intermediate.ID, "crl", "ca.crl.pem")
		cmd = exec.Command(openssl, "crl", "-in", crlPath, "-noout", "-verify", "-CAfile", intPath)
		if output, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("openssl crl: %v\n%s", e, output)
		}
		cmd = exec.Command(openssl, "verify", "-crl_check", "-CRLfile", crlPath, "-CAfile", rootPath, "-untrusted", intPath, leafPath)
		if output, e := cmd.CombinedOutput(); e == nil || !strings.Contains(string(output), "certificate revoked") {
			t.Fatalf("openssl did not detect revocation: %v\n%s", e, output)
		}
		configPath := filepath.Join(rootDir, "cas", intermediate.ID, "openssl.cnf")
		cmd = exec.Command(openssl, "ca", "-batch", "-config", configPath, "-revoke", clientPath, "-crl_reason", "superseded", "-passin", "pass:"+string(intPW))
		if output, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("openssl index update: %v\n%s", e, output)
		}
		_, _, clientStatus, e := certs.Get(intermediate.ID, client.Serial)
		if e != nil || clientStatus != 'R' {
			t.Fatalf("CAForge did not read OpenSSL index update: status=%c err=%v", clientStatus, e)
		}
	}
}
