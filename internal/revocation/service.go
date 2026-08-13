package revocation

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"

	"caforge/internal/domain"
	"caforge/internal/pki"
	"caforge/internal/store"
)

type Service struct {
	repo store.Repository
	now  func() time.Time
}

func New(repo store.Repository) *Service                   { return &Service{repo: repo, now: time.Now} }
func (s *Service) WithClock(now func() time.Time) *Service { s.now = now; return s }
func (s *Service) Revoke(caID, serial string, reason domain.RevocationReason, password []byte) error {
	if !reason.Valid() {
		return errors.New("无效的吊销原因")
	}
	return s.repo.WithCA(caID, func(tx *store.Transaction) error {
		if err := tx.Revoke(serial, s.now().UTC(), reason); err != nil {
			return err
		}
		return s.generateLocked(caID, tx, password)
	})
}
func (s *Service) Generate(caID string, password []byte) error {
	return s.repo.WithCA(caID, func(tx *store.Transaction) error { return s.generateLocked(caID, tx, password) })
}
func (s *Service) generateLocked(caID string, tx *store.Transaction, password []byte) error {
	certPEM, err := s.repo.ReadCACertificate(caID)
	if err != nil {
		return err
	}
	issuer, err := pki.ParseCertificate(certPEM)
	if err != nil {
		return err
	}
	keyPEM, err := s.repo.ReadCAKey(caID)
	if err != nil {
		return err
	}
	key, err := pki.ParsePrivateKey(keyPEM, password)
	if err != nil {
		return err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("CA 私钥不能用于签名")
	}
	entries, err := s.repo.ReadIndex(caID)
	if err != nil {
		return err
	}
	var revoked []x509.RevocationListEntry
	for _, e := range entries {
		if e.Status != 'R' || e.RevokedAt == nil {
			continue
		}
		n := new(big.Int)
		if _, ok := n.SetString(e.Serial, 16); !ok {
			return errors.New("索引包含无效序列号")
		}
		revoked = append(revoked, x509.RevocationListEntry{SerialNumber: n, RevocationTime: *e.RevokedAt, ReasonCode: int(e.Reason)})
	}
	number, err := tx.NextCRLNumber()
	if err != nil {
		return err
	}
	now := s.now().UTC()
	tmpl := &x509.RevocationList{Number: number, ThisUpdate: now, NextUpdate: now.Add(7 * 24 * time.Hour), RevokedCertificateEntries: revoked}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, signer)
	if err != nil {
		return err
	}
	return tx.WriteCRL(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), der)
}
func (s *Service) Read(caID string) (*x509.RevocationList, error) {
	b, err := s.repo.ReadCRL(caID)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("CRL PEM 损坏")
	}
	return x509.ParseRevocationList(block.Bytes)
}
func Reasons() []struct {
	Value domain.RevocationReason
	Label string
} {
	return []struct {
		Value domain.RevocationReason
		Label string
	}{{0, "未指定"}, {1, "密钥泄露"}, {2, "CA 泄露"}, {3, "从属关系变更"}, {4, "已被取代"}, {5, "停止运营"}, {6, "证书暂停"}, {9, "权限撤回"}, {10, "属性授权机构泄露"}}
}
func NormalizeSerial(v string) string { return strings.ToUpper(strings.TrimSpace(v)) }
