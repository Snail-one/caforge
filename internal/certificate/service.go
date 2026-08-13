package certificate

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"caforge/internal/domain"
	"caforge/internal/pki"
	"caforge/internal/store"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type AuthorityService interface{ Usable(string) error }

type DeploymentMaterials struct {
	CertificatePEM       []byte
	PrivateKeyPEM        []byte
	FullChainPEM         []byte
	CompleteChainPEM     []byte
	IntermediateChainPEM []byte
	RootCAPEM            []byte
	PrivateKeyEncrypted  bool
}

type FilePaths struct {
	Directory   string
	Certificate string
	PrivateKey  string
	Chain       string
	RequestCSR  string
}

type Service struct {
	repo        store.Repository
	authorities AuthorityService
	now         func() time.Time
}

func New(repo store.Repository, a AuthorityService) *Service {
	return &Service{repo: repo, authorities: a, now: time.Now}
}
func (s *Service) WithClock(now func() time.Time) *Service { s.now = now; return s }

func (s *Service) Issue(req domain.IssueRequest, caPassword []byte) (domain.Certificate, error) {
	var zero domain.Certificate
	if req.Algorithm == "" {
		req.Algorithm = domain.ECDSAP256
	}
	if req.Days == 0 {
		req.Days = 397
	}
	if err := s.authorities.Usable(req.CAID); err != nil {
		return zero, err
	}
	issuerPEM, issuerCert, issuerKey, chain, err := s.loadSigner(req.CAID, caPassword)
	_ = issuerPEM
	if err != nil {
		return zero, err
	}
	key, err := pki.GenerateKey(req.Algorithm, rand.Reader)
	if err != nil {
		return zero, err
	}
	pub, _ := pki.PublicKey(key)
	keyPassword := req.KeyPassword
	if !req.EncryptKey {
		keyPassword = nil
	}
	keyPEM, err := pki.MarshalPrivateKey(key, keyPassword, rand.Reader)
	if err != nil {
		return zero, err
	}
	var result domain.Certificate
	err = s.repo.WithCA(req.CAID, func(tx *store.Transaction) error {
		serial, e := tx.NextSerial()
		if e != nil {
			return e
		}
		tmpl, e := pki.LeafTemplate(req, serial, s.now(), issuerCert.NotAfter)
		if e != nil {
			return e
		}
		der, e := pki.CreateCertificate(tmpl, issuerCert, pub, issuerKey, rand.Reader)
		if e != nil {
			return e
		}
		certPEM := pki.EncodeCertificate(der)
		result = domain.Certificate{CAID: req.CAID, Serial: strings.ToUpper(serial.Text(16)), CommonName: req.CommonName, Profile: req.Profile, Algorithm: req.Algorithm, DNSNames: append([]string(nil), req.DNSNames...), IPAddresses: append([]string(nil), req.IPAddresses...), NotBefore: tmpl.NotBefore.UTC(), NotAfter: tmpl.NotAfter.UTC(), HasKey: true, RenewedFrom: req.RenewedFrom}
		fullChain := append(append([]byte{}, certPEM...), chain...)
		return tx.AddIssued(result, certPEM, keyPEM, nil, fullChain)
	})
	return result, err
}

func (s *Service) SignCSR(req domain.CSRRequest, caPassword []byte) (domain.Certificate, error) {
	var zero domain.Certificate
	if req.Days == 0 {
		req.Days = 397
	}
	if err := s.authorities.Usable(req.CAID); err != nil {
		return zero, err
	}
	csr, err := pki.ParseAndValidateCSR(req.CSRPEM, req.Profile)
	if err != nil {
		return zero, err
	}
	name := strings.TrimSpace(req.CommonName)
	if name == "" {
		name = csr.Subject.CommonName
	}
	if name == "" {
		return zero, errors.New("CSR 和请求均未提供通用名称")
	}
	alg, err := pki.AlgorithmOfPublicKey(csr.PublicKey)
	if err != nil {
		return zero, err
	}
	_, issuerCert, issuerKey, chain, err := s.loadSigner(req.CAID, caPassword)
	if err != nil {
		return zero, err
	}
	ips := make([]string, len(csr.IPAddresses))
	for i, ip := range csr.IPAddresses {
		ips[i] = ip.String()
	}
	issue := domain.IssueRequest{CAID: req.CAID, CommonName: name, Profile: req.Profile, Algorithm: alg, DNSNames: csr.DNSNames, IPAddresses: ips, Days: req.Days}
	var result domain.Certificate
	err = s.repo.WithCA(req.CAID, func(tx *store.Transaction) error {
		serial, e := tx.NextSerial()
		if e != nil {
			return e
		}
		tmpl, e := pki.LeafTemplate(issue, serial, s.now(), issuerCert.NotAfter)
		if e != nil {
			return e
		}
		der, e := pki.CreateCertificate(tmpl, issuerCert, csr.PublicKey, issuerKey, rand.Reader)
		if e != nil {
			return e
		}
		certPEM := pki.EncodeCertificate(der)
		result = domain.Certificate{CAID: req.CAID, Serial: strings.ToUpper(serial.Text(16)), CommonName: name, Profile: req.Profile, Algorithm: alg, DNSNames: csr.DNSNames, IPAddresses: ips, NotBefore: tmpl.NotBefore.UTC(), NotAfter: tmpl.NotAfter.UTC(), HasKey: false}
		return tx.AddIssued(result, certPEM, nil, req.CSRPEM, append(append([]byte{}, certPEM...), chain...))
	})
	return result, err
}

func (s *Service) loadSigner(id string, password []byte) ([]byte, *x509.Certificate, any, []byte, error) {
	certPEM, err := s.repo.ReadCACertificate(id)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cert, err := pki.ParseCertificate(certPEM)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keyPEM, err := s.repo.ReadCAKey(id)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	key, err := pki.ParsePrivateKey(keyPEM, password)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	chain, err := s.AuthorityChain(id)
	return certPEM, cert, key, chain, err
}
func (s *Service) AuthorityChain(id string) ([]byte, error) {
	var out bytes.Buffer
	seen := map[string]bool{}
	for id != "" {
		if seen[id] {
			return nil, errors.New("CA 父级关系形成循环")
		}
		seen[id] = true
		a, err := s.repo.LoadAuthority(id)
		if err != nil {
			return nil, err
		}
		b, err := s.repo.ReadCACertificate(id)
		if err != nil {
			return nil, err
		}
		out.Write(b)
		id = a.ParentID
	}
	return out.Bytes(), nil
}
func (s *Service) List(caID string) ([]domain.Certificate, error) {
	return s.repo.ListCertificates(caID)
}
func (s *Service) Get(caID, serial string) (domain.Certificate, *x509.Certificate, byte, error) {
	c, b, _, _, e := s.repo.LoadCertificate(caID, serial)
	if e != nil {
		return c, nil, 0, e
	}
	parsed, e := pki.ParseCertificate(b)
	if e != nil {
		return c, nil, 0, e
	}
	status := byte('?')
	entries, e := s.repo.ReadIndex(caID)
	if e != nil {
		return c, nil, 0, e
	}
	for _, v := range entries {
		if v.Serial == strings.ToUpper(serial) {
			status = v.Status
			break
		}
	}
	if status == 'V' && !s.now().Before(parsed.NotAfter) {
		status = 'E'
	}
	return c, parsed, status, nil
}

func (s *Service) FilePaths(caID, serial string) (FilePaths, error) {
	var paths FilePaths
	meta, _, _, _, err := s.repo.LoadCertificate(caID, serial)
	if err != nil {
		return paths, err
	}
	base := filepath.Join(s.repo.Root(), "cas", caID, "issued", strings.ToUpper(serial))
	paths = FilePaths{
		Directory:   base,
		Certificate: filepath.Join(base, "cert.pem"),
		Chain:       filepath.Join(base, "chain.pem"),
	}
	if meta.HasKey {
		paths.PrivateKey = filepath.Join(base, "key.pem")
	} else if meta.Profile != domain.Intermediate {
		paths.RequestCSR = filepath.Join(base, "request.csr.pem")
	}
	return paths, nil
}

func (s *Service) DeploymentMaterials(caID, serial string) (DeploymentMaterials, error) {
	var materials DeploymentMaterials
	_, certificatePEM, privateKeyPEM, chainPEM, err := s.repo.LoadCertificate(caID, serial)
	if err != nil {
		return materials, err
	}
	certificates, blocks, err := parseCertificateBlocks(chainPEM)
	if err != nil {
		return materials, err
	}
	if len(certificates) < 2 {
		return materials, errors.New("证书链缺少根 CA")
	}
	leaf, err := pki.ParseCertificate(certificatePEM)
	if err != nil {
		return materials, err
	}
	if !bytes.Equal(certificates[0].Raw, leaf.Raw) {
		return materials, errors.New("证书链首项不是当前证书")
	}
	for index := 0; index < len(certificates)-1; index++ {
		if err = certificates[index].CheckSignatureFrom(certificates[index+1]); err != nil {
			return materials, fmt.Errorf("证书链第 %d 项无法由第 %d 项验证: %w", index+1, index+2, err)
		}
	}
	root := certificates[len(certificates)-1]
	if root.Subject.String() != root.Issuer.String() || root.CheckSignatureFrom(root) != nil {
		return materials, errors.New("证书链末项不是有效的自签名根 CA")
	}

	materials.CertificatePEM = append([]byte(nil), blocks[0]...)
	materials.CompleteChainPEM = bytes.Join(blocks, nil)
	materials.FullChainPEM = bytes.Join(blocks[:len(blocks)-1], nil)
	materials.RootCAPEM = append([]byte(nil), blocks[len(blocks)-1]...)
	if len(blocks) > 2 {
		materials.IntermediateChainPEM = bytes.Join(blocks[1:len(blocks)-1], nil)
	}
	if len(privateKeyPEM) > 0 {
		keyBlock, rest := pem.Decode(privateKeyPEM)
		if keyBlock == nil || len(bytes.TrimSpace(rest)) != 0 {
			return materials, errors.New("保存的私钥 PEM 损坏")
		}
		if keyBlock.Type != "PRIVATE KEY" && keyBlock.Type != "ENCRYPTED PRIVATE KEY" {
			return materials, fmt.Errorf("不支持的私钥 PEM 类型 %q", keyBlock.Type)
		}
		materials.PrivateKeyPEM = pem.EncodeToMemory(keyBlock)
		materials.PrivateKeyEncrypted = keyBlock.Type == "ENCRYPTED PRIVATE KEY"
	}
	return materials, nil
}

func parseCertificateBlocks(data []byte) ([]*x509.Certificate, [][]byte, error) {
	var certificates []*x509.Certificate
	var blocks [][]byte
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, nil, errors.New("证书链 PEM 损坏")
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("证书链包含非证书 PEM 块 %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certificates = append(certificates, certificate)
		blocks = append(blocks, pem.EncodeToMemory(block))
	}
	return certificates, blocks, nil
}
func (s *Service) Renew(caID, serial string, days int, caPassword, keyPassword []byte, encrypt bool) (domain.Certificate, error) {
	old, _, _, e := s.Get(caID, serial)
	if e != nil {
		return domain.Certificate{}, e
	}
	return s.Issue(domain.IssueRequest{CAID: caID, CommonName: old.CommonName, Profile: old.Profile, Algorithm: old.Algorithm, DNSNames: old.DNSNames, IPAddresses: old.IPAddresses, Days: days, EncryptKey: encrypt, KeyPassword: keyPassword, RenewedFrom: old.Serial}, caPassword)
}

func (s *Service) Export(caID, serial string, format domain.ExportFormat, keyPassword, exportPassword []byte) ([]byte, error) {
	_, certPEM, keyPEM, chain, e := s.repo.LoadCertificate(caID, serial)
	if e != nil {
		return nil, e
	}
	if format == domain.ExportPEM {
		var b bytes.Buffer
		b.Write(certPEM)
		if len(keyPEM) > 0 {
			b.Write(keyPEM)
		}
		b.Write(chainWithoutLeaf(chain))
		return b.Bytes(), nil
	}
	if format != domain.ExportPKCS12 {
		return nil, errors.New("不支持的导出格式")
	}
	if len(exportPassword) == 0 {
		return nil, errors.New("PKCS#12 必须设置导出口令")
	}
	if len(keyPEM) == 0 {
		return nil, errors.New("CSR 签发证书不含私钥，无法导出 PKCS#12")
	}
	key, e := pki.ParsePrivateKey(keyPEM, keyPassword)
	if e != nil {
		return nil, e
	}
	cert, e := pki.ParseCertificate(certPEM)
	if e != nil {
		return nil, e
	}
	caCerts, e := parseCertificates(chainWithoutLeaf(chain))
	if e != nil {
		return nil, e
	}
	return pkcs12.Modern2023.Encode(key, cert, caCerts, string(exportPassword))
}
func chainWithoutLeaf(chain []byte) []byte { _, rest := pem.Decode(chain); return rest }
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(data) > 0 {
		b, rest := pem.Decode(data)
		if b == nil {
			if len(bytes.TrimSpace(data)) > 0 {
				return nil, errors.New("证书链 PEM 损坏")
			}
			break
		}
		data = rest
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, nil
}

func ValidateSANs(dns, ips []string) error {
	if len(dns)+len(ips) == 0 {
		return errors.New("至少需要一个 SAN")
	}
	for _, v := range ips {
		if net.ParseIP(strings.TrimSpace(v)) == nil {
			return fmt.Errorf("无效 IP: %s", v)
		}
	}
	for _, v := range dns {
		if err := pki.ValidateDNSName(v); err != nil {
			return err
		}
	}
	return nil
}
