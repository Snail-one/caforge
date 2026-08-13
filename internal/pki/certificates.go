package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"caforge/internal/domain"
)

func RootTemplate(name string, serial *big.Int, now time.Time, days, maxPath int) *x509.Certificate {
	return &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, days), IsCA: true, BasicConstraintsValid: true, MaxPathLen: maxPath, MaxPathLenZero: maxPath == 0, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
}

func IntermediateTemplate(name string, serial *big.Int, now, issuerExpiry time.Time, days int) (*x509.Certificate, error) {
	t := RootTemplate(name, serial, now, days, 0)
	if !t.NotAfter.Before(issuerExpiry) {
		t.NotAfter = issuerExpiry
	}
	if !t.NotAfter.After(t.NotBefore) {
		return nil, errors.New("父 CA 已过期")
	}
	return t, nil
}

func LeafTemplate(req domain.IssueRequest, serial *big.Int, now, issuerExpiry time.Time) (*x509.Certificate, error) {
	if strings.TrimSpace(req.CommonName) == "" {
		return nil, errors.New("通用名称不能为空")
	}
	if req.Days <= 0 {
		return nil, errors.New("有效天数必须为正数")
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: strings.TrimSpace(req.CommonName)}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, req.Days), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if !t.NotAfter.Before(issuerExpiry) {
		t.NotAfter = issuerExpiry
	}
	if !t.NotAfter.After(t.NotBefore) {
		return nil, errors.New("签发 CA 已过期")
	}
	for _, s := range req.DNSNames {
		s = strings.TrimSpace(s)
		if s != "" {
			if err := ValidateDNSName(s); err != nil {
				return nil, err
			}
			t.DNSNames = append(t.DNSNames, s)
		}
	}
	for _, s := range req.IPAddresses {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return nil, fmt.Errorf("无效 IP SAN: %s", s)
		}
		t.IPAddresses = append(t.IPAddresses, ip)
	}
	switch req.Profile {
	case domain.Server:
		if len(t.DNSNames)+len(t.IPAddresses) == 0 {
			return nil, errors.New("服务器证书至少需要一个 DNS 或 IP SAN")
		}
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case domain.Client:
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, fmt.Errorf("无效证书模板 %q", req.Profile)
	}
	return t, nil
}

func CreateCertificate(t, parent *x509.Certificate, pub, signer any, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	return x509.CreateCertificate(random, t, parent, pub, signer)
}

func ParseAndValidateCSR(data []byte, profile domain.Profile) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE REQUEST" && b.Type != "NEW CERTIFICATE REQUEST" {
		return nil, errors.New("不是有效的 PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	if err = csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR 签名无效: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 3072 {
			return nil, errors.New("CSR RSA 密钥不得低于 3072 位")
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			return nil, errors.New("CSR ECDSA 曲线不得低于 P-256")
		}
	default:
		return nil, fmt.Errorf("CSR 使用了不支持的公钥算法 %T", k)
	}
	if profile == domain.Server && len(csr.DNSNames)+len(csr.IPAddresses) == 0 {
		return nil, errors.New("服务器 CSR 至少需要一个 DNS 或 IP SAN")
	}
	for _, name := range csr.DNSNames {
		if err := ValidateDNSName(name); err != nil {
			return nil, fmt.Errorf("CSR %w", err)
		}
	}
	if profile != domain.Server && profile != domain.Client {
		return nil, errors.New("CSR 只能签发服务器或客户端证书")
	}
	return csr, nil
}

func ValidateDNSName(name string) error {
	original := name
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	if name == "" || len(name) > 253 {
		return fmt.Errorf("无效 DNS SAN: %s", original)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("无效 DNS SAN: %s", original)
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return fmt.Errorf("无效 DNS SAN: %s（国际化域名请使用 punycode）", original)
			}
		}
	}
	return nil
}

func AlgorithmOfPublicKey(pub any) (domain.Algorithm, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() >= 4096 {
			return domain.RSA4096, nil
		}
		if k.N.BitLen() >= 3072 {
			return domain.RSA3072, nil
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize >= 384 {
			return domain.ECDSAP384, nil
		}
		if k.Curve.Params().BitSize >= 256 {
			return domain.ECDSAP256, nil
		}
	}
	return "", fmt.Errorf("不支持或强度不足的公钥 %T", pub)
}
