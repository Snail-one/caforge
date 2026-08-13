package authority

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"time"

	"caforge/internal/domain"
	"caforge/internal/pki"
	"caforge/internal/store"
)

type CreateRootRequest struct {
	Name             string
	Algorithm        domain.Algorithm
	Days, MaxPathLen int
	Password         []byte
}
type CreateIntermediateRequest struct {
	ParentID, Name           string
	Algorithm                domain.Algorithm
	Days                     int
	ParentPassword, Password []byte
}
type Service struct {
	repo store.Repository
	now  func() time.Time
}

func New(repo store.Repository) *Service                   { return &Service{repo: repo, now: time.Now} }
func (s *Service) WithClock(now func() time.Time) *Service { s.now = now; return s }

func (s *Service) CreateRoot(req CreateRootRequest) (domain.Authority, error) {
	var zero domain.Authority
	if strings.TrimSpace(req.Name) == "" {
		return zero, errors.New("CA 名称不能为空")
	}
	if len(req.Password) == 0 {
		return zero, errors.New("CA 私钥必须设置口令")
	}
	if req.Algorithm == "" {
		req.Algorithm = domain.ECDSAP384
	}
	if req.Days == 0 {
		req.Days = 3650
	}
	if req.MaxPathLen == 0 {
		req.MaxPathLen = 1
	}
	key, err := pki.GenerateKey(req.Algorithm, rand.Reader)
	if err != nil {
		return zero, err
	}
	pub, _ := pki.PublicKey(key)
	serial, err := randomSerial()
	if err != nil {
		return zero, err
	}
	now := s.now()
	tmpl := pki.RootTemplate(req.Name, serial, now, req.Days, req.MaxPathLen)
	der, err := pki.CreateCertificate(tmpl, tmpl, pub, key, rand.Reader)
	if err != nil {
		return zero, err
	}
	keyPEM, err := pki.MarshalPrivateKey(key, req.Password, rand.Reader)
	if err != nil {
		return zero, err
	}
	id, err := newID(req.Name)
	if err != nil {
		return zero, err
	}
	a := domain.Authority{ID: id, Name: strings.TrimSpace(req.Name), Algorithm: req.Algorithm, CreatedAt: now.UTC(), NotAfter: tmpl.NotAfter.UTC(), MaxPathLen: req.MaxPathLen, DefaultDays: 397}
	if err = s.repo.CreateAuthority(a, pki.EncodeCertificate(der), keyPEM); err != nil {
		return zero, err
	}
	return a, s.repo.SetCurrentCA(a.ID)
}

func (s *Service) CreateIntermediate(req CreateIntermediateRequest) (domain.Authority, error) {
	var zero domain.Authority
	if strings.TrimSpace(req.Name) == "" {
		return zero, errors.New("CA 名称不能为空")
	}
	if len(req.Password) == 0 {
		return zero, errors.New("中间 CA 私钥必须设置口令")
	}
	parent, err := s.repo.LoadAuthority(req.ParentID)
	if err != nil {
		return zero, err
	}
	if !parent.IsRoot() {
		return zero, errors.New("首版仅支持一层中间 CA")
	}
	if req.Algorithm == "" {
		req.Algorithm = domain.ECDSAP384
	}
	if req.Days == 0 {
		req.Days = 1825
	}
	parentCertPEM, err := s.repo.ReadCACertificate(parent.ID)
	if err != nil {
		return zero, err
	}
	parentCert, err := pki.ParseCertificate(parentCertPEM)
	if err != nil {
		return zero, err
	}
	parentKeyPEM, err := s.repo.ReadCAKey(parent.ID)
	if err != nil {
		return zero, err
	}
	parentKey, err := pki.ParsePrivateKey(parentKeyPEM, req.ParentPassword)
	if err != nil {
		return zero, err
	}
	key, err := pki.GenerateKey(req.Algorithm, rand.Reader)
	if err != nil {
		return zero, err
	}
	pub, _ := pki.PublicKey(key)
	keyPEM, err := pki.MarshalPrivateKey(key, req.Password, rand.Reader)
	if err != nil {
		return zero, err
	}
	now := s.now()
	var result domain.Authority
	err = s.repo.WithCA(parent.ID, func(tx *store.Transaction) error {
		serial, e := tx.NextSerial()
		if e != nil {
			return e
		}
		tmpl, e := pki.IntermediateTemplate(req.Name, serial, now, parentCert.NotAfter, req.Days)
		if e != nil {
			return e
		}
		der, e := pki.CreateCertificate(tmpl, parentCert, pub, parentKey, rand.Reader)
		if e != nil {
			return e
		}
		certPEM := pki.EncodeCertificate(der)
		id, e := newID(req.Name)
		if e != nil {
			return e
		}
		result = domain.Authority{ID: id, Name: strings.TrimSpace(req.Name), ParentID: parent.ID, IssuerSerial: strings.ToUpper(serial.Text(16)), Algorithm: req.Algorithm, CreatedAt: now.UTC(), NotAfter: tmpl.NotAfter.UTC(), MaxPathLen: 0, DefaultDays: 397}
		meta := domain.Certificate{CAID: parent.ID, Serial: result.IssuerSerial, CommonName: result.Name, Profile: domain.Intermediate, Algorithm: req.Algorithm, NotBefore: tmpl.NotBefore, NotAfter: tmpl.NotAfter}
		if e = tx.AddIssued(meta, certPEM, nil, nil, append(append([]byte{}, certPEM...), parentCertPEM...)); e != nil {
			return e
		}
		return s.repo.CreateAuthority(result, certPEM, keyPEM)
	})
	if err != nil {
		return zero, err
	}
	if err = s.repo.SetCurrentCA(result.ID); err != nil {
		return zero, err
	}
	return result, nil
}

func (s *Service) List() ([]domain.Authority, error) { return s.repo.ListAuthorities() }
func (s *Service) Get(id string) (domain.Authority, *x509.Certificate, error) {
	a, e := s.repo.LoadAuthority(id)
	if e != nil {
		return a, nil, e
	}
	b, e := s.repo.ReadCACertificate(id)
	if e != nil {
		return a, nil, e
	}
	c, e := pki.ParseCertificate(b)
	return a, c, e
}
func (s *Service) Select(id string) error   { return s.repo.SetCurrentCA(id) }
func (s *Service) Current() (string, error) { return s.repo.CurrentCA() }

func (s *Service) Usable(id string) error {
	a, err := s.repo.LoadAuthority(id)
	if err != nil {
		return err
	}
	if !s.now().Before(a.NotAfter) {
		return errors.New("CA 已过期")
	}
	if a.ParentID != "" {
		entries, err := s.repo.ReadIndex(a.ParentID)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Serial == a.IssuerSerial {
				if e.Status == 'R' {
					return errors.New("中间 CA 已被父 CA 吊销，禁止继续签发")
				}
				return nil
			}
		}
		return errors.New("父 CA 索引中不存在该中间 CA")
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err == nil && n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, err
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

func newID(name string) (string, error) {
	slug := slugRE.ReplaceAllString(strings.ToLower(name), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "ca"
	}
	if len(slug) > 48 {
		slug = slug[:48]
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return slug + "-" + hex.EncodeToString(b), nil
}
