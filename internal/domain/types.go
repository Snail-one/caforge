package domain

import (
	"crypto/x509"
	"time"
)

type Algorithm string

const (
	ECDSAP256 Algorithm = "ecdsa-p256"
	ECDSAP384 Algorithm = "ecdsa-p384"
	RSA3072   Algorithm = "rsa-3072"
	RSA4096   Algorithm = "rsa-4096"
)

type Profile string

const (
	Server       Profile = "server"
	Client       Profile = "client"
	Intermediate Profile = "intermediate-ca"
)

type Authority struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ParentID     string    `json:"parent_id,omitempty"`
	IssuerSerial string    `json:"issuer_serial,omitempty"`
	Algorithm    Algorithm `json:"algorithm"`
	CreatedAt    time.Time `json:"created_at"`
	NotAfter     time.Time `json:"not_after"`
	MaxPathLen   int       `json:"max_path_len"`
	DefaultDays  int       `json:"default_days"`
}

func (a Authority) IsRoot() bool { return a.ParentID == "" }

type Certificate struct {
	CAID        string    `json:"ca_id"`
	Serial      string    `json:"serial"`
	CommonName  string    `json:"common_name"`
	Profile     Profile   `json:"profile"`
	Algorithm   Algorithm `json:"algorithm"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	IPAddresses []string  `json:"ip_addresses,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	HasKey      bool      `json:"has_key"`
	RenewedFrom string    `json:"renewed_from,omitempty"`
}

type CertificateRecord struct {
	Certificate Certificate
	Parsed      *x509.Certificate
	Status      byte
	RevokedAt   *time.Time
	Reason      int
}

type RevocationReason int

const (
	Unspecified          RevocationReason = 0
	KeyCompromise        RevocationReason = 1
	CACompromise         RevocationReason = 2
	AffiliationChanged   RevocationReason = 3
	Superseded           RevocationReason = 4
	CessationOfOperation RevocationReason = 5
	CertificateHold      RevocationReason = 6
	RemoveFromCRL        RevocationReason = 8
	PrivilegeWithdrawn   RevocationReason = 9
	AACompromise         RevocationReason = 10
)

func (r RevocationReason) Valid() bool {
	switch r {
	case Unspecified, KeyCompromise, CACompromise, AffiliationChanged, Superseded,
		CessationOfOperation, CertificateHold, PrivilegeWithdrawn, AACompromise:
		return true
	default:
		return false
	}
}

func (r RevocationReason) OpenSSLName() string {
	return map[RevocationReason]string{
		Unspecified: "unspecified", KeyCompromise: "keyCompromise", CACompromise: "CACompromise",
		AffiliationChanged: "affiliationChanged", Superseded: "superseded",
		CessationOfOperation: "cessationOfOperation", CertificateHold: "certificateHold",
		PrivilegeWithdrawn: "privilegeWithdrawn", AACompromise: "AACompromise",
	}[r]
}

type IssueRequest struct {
	CAID, CommonName string
	Profile          Profile
	Algorithm        Algorithm
	DNSNames         []string
	IPAddresses      []string
	Days             int
	EncryptKey       bool
	KeyPassword      []byte
	RenewedFrom      string
}

type CSRRequest struct {
	CAID, CommonName string
	Profile          Profile
	CSRPEM           []byte
	Days             int
}

type ExportFormat string

const (
	ExportPEM    ExportFormat = "pem"
	ExportPKCS12 ExportFormat = "pkcs12"
)
