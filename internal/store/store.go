package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"caforge/internal/domain"
)

var safeID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var safeSerial = regexp.MustCompile(`^[0-9A-F]+$`)

type Store struct{ root string }

// Repository is the persistence boundary used by application services.
type Repository interface {
	Init() error
	Root() string
	CreateAuthority(domain.Authority, []byte, []byte) error
	LoadAuthority(string) (domain.Authority, error)
	ListAuthorities() ([]domain.Authority, error)
	ReadCACertificate(string) ([]byte, error)
	ReadCAKey(string) ([]byte, error)
	SetCurrentCA(string) error
	CurrentCA() (string, error)
	WithCA(string, func(*Transaction) error) error
	ReadIndex(string) ([]IndexEntry, error)
	LoadCertificate(string, string) (domain.Certificate, []byte, []byte, []byte, error)
	ListCertificates(string) ([]domain.Certificate, error)
	ReadCRL(string) ([]byte, error)
}

func New(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("数据目录不能为空")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}
func (s *Store) Root() string { return s.root }
func (s *Store) Init() error {
	if err := os.MkdirAll(filepath.Join(s.root, "cas"), 0700); err != nil {
		return err
	}
	if err := os.Chmod(s.root, 0700); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(s.root, "cas"), 0700)
}
func validateID(id string) error {
	if !safeID.MatchString(id) {
		return fmt.Errorf("无效 CA ID %q", id)
	}
	return nil
}
func validateSerial(v string) error {
	if !safeSerial.MatchString(v) {
		return fmt.Errorf("无效序列号 %q", v)
	}
	return nil
}
func (s *Store) CADir(id string) (string, error) {
	if err := validateID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.root, "cas", id), nil
}

func (s *Store) CreateAuthority(a domain.Authority, certPEM, keyPEM []byte) error {
	dir, err := s.CADir(a.ID)
	if err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("CA %s 已存在", a.ID)
		}
		return err
	}
	for _, p := range []string{"certs", "private", "csr", "newcerts", "issued", "crl"} {
		if err = os.Mkdir(filepath.Join(dir, p), 0700); err != nil {
			os.RemoveAll(dir)
			return err
		}
	}
	fail := func(e error) error { os.RemoveAll(dir); return e }
	meta, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fail(err)
	}
	meta = append(meta, '\n')
	files := []struct {
		name string
		data []byte
		mode fs.FileMode
	}{
		{"ca.json", meta, 0600}, {"certs/ca.cert.pem", certPEM, 0644}, {"private/ca.key.pem", keyPEM, 0600},
		{"index.txt", nil, 0600}, {"index.txt.attr", []byte("unique_subject = no\n"), 0600}, {"serial", []byte("1000\n"), 0600}, {"crlnumber", []byte("1000\n"), 0600},
		{"openssl.cnf", []byte(opensslConfig(dir)), 0644},
	}
	for _, f := range files {
		if err = writeAtomic(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return fail(err)
		}
	}
	return nil
}

func opensslConfig(dir string) string {
	return fmt.Sprintf(`[ ca ]
default_ca = CA_default
[ CA_default ]
dir = %s
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/certs/ca.cert.pem
private_key = $dir/private/ca.key.pem
serial = $dir/serial
crlnumber = $dir/crlnumber
crl = $dir/crl/ca.crl.pem
default_md = sha384
default_days = 397
default_crl_days = 7
policy = policy_any
unique_subject = no
copy_extensions = none
[ policy_any ]
commonName = supplied
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
emailAddress = optional
`, dir)
}

func (s *Store) LoadAuthority(id string) (domain.Authority, error) {
	var a domain.Authority
	dir, err := s.CADir(id)
	if err != nil {
		return a, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "ca.json"))
	if err != nil {
		return a, err
	}
	err = json.Unmarshal(b, &a)
	return a, err
}
func (s *Store) ListAuthorities() ([]domain.Authority, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "cas"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []domain.Authority
	for _, e := range entries {
		if !e.IsDir() || validateID(e.Name()) != nil {
			continue
		}
		a, err := s.LoadAuthority(e.Name())
		if err == nil {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *Store) ReadCACertificate(id string) ([]byte, error) {
	d, e := s.CADir(id)
	if e != nil {
		return nil, e
	}
	return os.ReadFile(filepath.Join(d, "certs/ca.cert.pem"))
}
func (s *Store) ReadCAKey(id string) ([]byte, error) {
	d, e := s.CADir(id)
	if e != nil {
		return nil, e
	}
	return os.ReadFile(filepath.Join(d, "private/ca.key.pem"))
}
func (s *Store) SetCurrentCA(id string) error {
	if _, err := s.LoadAuthority(id); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.root, "current_ca"), []byte(id+"\n"), 0600)
}
func (s *Store) CurrentCA() (string, error) {
	b, err := os.ReadFile(filepath.Join(s.root, "current_ca"))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if err = validateID(id); err != nil {
		return "", err
	}
	return id, nil
}

type IndexEntry struct {
	Status                    byte
	Expires                   time.Time
	RevokedAt                 *time.Time
	Reason                    domain.RevocationReason
	Serial, Filename, Subject string
}

func parseIndexTime(v string) (time.Time, error) { return time.Parse("060102150405Z", v) }
func formatIndexTime(v time.Time) string         { return v.UTC().Format("060102150405Z") }
func ParseIndex(data []byte) ([]IndexEntry, error) {
	var out []IndexEntry
	s := bufio.NewScanner(strings.NewReader(string(data)))
	line := 0
	for s.Scan() {
		line++
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		f := strings.Split(s.Text(), "\t")
		if len(f) != 6 || len(f[0]) != 1 {
			return nil, fmt.Errorf("index.txt 第 %d 行格式无效", line)
		}
		e := IndexEntry{Status: f[0][0], Serial: strings.ToUpper(f[3]), Filename: f[4], Subject: f[5]}
		if validateSerial(e.Serial) != nil {
			return nil, fmt.Errorf("index.txt 第 %d 行序列号无效", line)
		}
		var err error
		e.Expires, err = parseIndexTime(f[1])
		if err != nil {
			return nil, fmt.Errorf("index.txt 第 %d 行到期时间无效", line)
		}
		if f[2] != "" {
			p := strings.Split(f[2], ",")
			t, er := parseIndexTime(p[0])
			if er != nil {
				return nil, fmt.Errorf("index.txt 第 %d 行吊销时间无效", line)
			}
			e.RevokedAt = &t
			if len(p) > 1 {
				e.Reason = parseReasonName(p[1])
			}
		}
		out = append(out, e)
	}
	return out, s.Err()
}
func parseReasonName(s string) domain.RevocationReason {
	for _, r := range []domain.RevocationReason{0, 1, 2, 3, 4, 5, 6, 9, 10} {
		if r.OpenSSLName() == s {
			return r
		}
	}
	return domain.Unspecified
}
func EncodeIndex(entries []IndexEntry) []byte {
	var b strings.Builder
	for _, e := range entries {
		rev := ""
		if e.RevokedAt != nil {
			rev = formatIndexTime(*e.RevokedAt)
			if n := e.Reason.OpenSSLName(); n != "" && e.Reason != domain.Unspecified {
				rev += "," + n
			}
		}
		fmt.Fprintf(&b, "%c\t%s\t%s\t%s\t%s\t%s\n", e.Status, formatIndexTime(e.Expires), rev, e.Serial, e.Filename, e.Subject)
	}
	return []byte(b.String())
}

func (s *Store) ReadIndex(id string) ([]IndexEntry, error) {
	d, e := s.CADir(id)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(filepath.Join(d, "index.txt"))
	if e != nil {
		return nil, e
	}
	return ParseIndex(b)
}

type Transaction struct {
	store          *Store
	dir            string
	originalSerial []byte
	originalCRL    []byte
	originalIndex  []byte
	created        []string
}

func (s *Store) WithCA(id string, fn func(*Transaction) error) error {
	dir, err := s.CADir(id)
	if err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	tx := &Transaction{store: s, dir: dir}
	if tx.originalSerial, err = os.ReadFile(filepath.Join(dir, "serial")); err != nil {
		return err
	}
	if tx.originalCRL, err = os.ReadFile(filepath.Join(dir, "crlnumber")); err != nil {
		return err
	}
	if tx.originalIndex, err = os.ReadFile(filepath.Join(dir, "index.txt")); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		_ = writeAtomic(filepath.Join(dir, "serial"), tx.originalSerial, 0600)
		_ = writeAtomic(filepath.Join(dir, "crlnumber"), tx.originalCRL, 0600)
		_ = writeAtomic(filepath.Join(dir, "index.txt"), tx.originalIndex, 0600)
		for _, p := range tx.created {
			_ = os.RemoveAll(p)
		}
		return err
	}
	return nil
}
func nextHex(path string) (*big.Int, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	v := strings.ToUpper(strings.TrimSpace(string(b)))
	if validateSerial(v) != nil {
		return nil, "", errors.New("序列号文件损坏")
	}
	n := new(big.Int)
	if _, ok := n.SetString(v, 16); !ok {
		return nil, "", errors.New("序列号文件损坏")
	}
	next := new(big.Int).Add(new(big.Int).Set(n), big.NewInt(1))
	return n, strings.ToUpper(next.Text(16)) + "\n", nil
}
func (tx *Transaction) NextSerial() (*big.Int, error) {
	n, next, err := nextHex(filepath.Join(tx.dir, "serial"))
	if err != nil {
		return nil, err
	}
	if err = writeAtomic(filepath.Join(tx.dir, "serial"), []byte(next), 0600); err != nil {
		return nil, err
	}
	return n, nil
}
func (tx *Transaction) NextCRLNumber() (*big.Int, error) {
	n, next, err := nextHex(filepath.Join(tx.dir, "crlnumber"))
	if err != nil {
		return nil, err
	}
	if err = writeAtomic(filepath.Join(tx.dir, "crlnumber"), []byte(next), 0600); err != nil {
		return nil, err
	}
	return n, nil
}
func (tx *Transaction) AddIssued(c domain.Certificate, certPEM, keyPEM, csrPEM, chainPEM []byte) error {
	serial := strings.ToUpper(c.Serial)
	if err := validateSerial(serial); err != nil {
		return err
	}
	issued := filepath.Join(tx.dir, "issued", serial)
	if _, err := os.Stat(issued); err == nil {
		return fmt.Errorf("序列号 %s 已存在", serial)
	}
	if err := os.MkdirAll(issued, 0700); err != nil {
		return err
	}
	tx.created = append(tx.created, issued)
	meta, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	meta = append(meta, '\n')
	files := []struct {
		n string
		b []byte
		m fs.FileMode
	}{{"cert.json", meta, 0600}, {"cert.pem", certPEM, 0644}, {"chain.pem", chainPEM, 0644}}
	if len(keyPEM) > 0 {
		files = append(files, struct {
			n string
			b []byte
			m fs.FileMode
		}{"key.pem", keyPEM, 0600})
	}
	if len(csrPEM) > 0 {
		files = append(files, struct {
			n string
			b []byte
			m fs.FileMode
		}{"request.csr.pem", csrPEM, 0644})
	}
	for _, f := range files {
		if err = writeAtomic(filepath.Join(issued, f.n), f.b, f.m); err != nil {
			return err
		}
	}
	if err = writeAtomic(filepath.Join(tx.dir, "newcerts", serial+".pem"), certPEM, 0644); err != nil {
		return err
	}
	tx.created = append(tx.created, filepath.Join(tx.dir, "newcerts", serial+".pem"))
	entries, err := ParseIndex(tx.originalIndex)
	if err != nil {
		return err
	}
	entries = append(entries, IndexEntry{Status: 'V', Expires: c.NotAfter, Serial: serial, Filename: "unknown", Subject: "/CN=" + escapeSubject(c.CommonName)})
	return writeAtomic(filepath.Join(tx.dir, "index.txt"), EncodeIndex(entries), 0600)
}
func escapeSubject(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "/", "\\/")
	return r.Replace(s)
}
func (tx *Transaction) Revoke(serial string, at time.Time, reason domain.RevocationReason) error {
	serial = strings.ToUpper(serial)
	if validateSerial(serial) != nil {
		return errors.New("无效序列号")
	}
	entries, err := ParseIndex(tx.originalIndex)
	if err != nil {
		return err
	}
	found := false
	for i := range entries {
		if entries[i].Serial == serial {
			found = true
			if entries[i].Status == 'R' {
				return errors.New("证书已经吊销")
			}
			entries[i].Status = 'R'
			entries[i].RevokedAt = &at
			entries[i].Reason = reason
		}
	}
	if !found {
		return errors.New("未找到该证书")
	}
	return writeAtomic(filepath.Join(tx.dir, "index.txt"), EncodeIndex(entries), 0600)
}
func (tx *Transaction) WriteCRL(pemData, der []byte) error {
	if err := writeAtomic(filepath.Join(tx.dir, "crl/ca.crl.pem"), pemData, 0644); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(tx.dir, "crl/ca.crl.der"), der, 0644)
}

func (s *Store) LoadCertificate(caID, serial string) (domain.Certificate, []byte, []byte, []byte, error) {
	var c domain.Certificate
	if err := validateSerial(strings.ToUpper(serial)); err != nil {
		return c, nil, nil, nil, err
	}
	d, err := s.CADir(caID)
	if err != nil {
		return c, nil, nil, nil, err
	}
	base := filepath.Join(d, "issued", strings.ToUpper(serial))
	b, err := os.ReadFile(filepath.Join(base, "cert.json"))
	if err != nil {
		return c, nil, nil, nil, err
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, nil, nil, nil, err
	}
	cert, err := os.ReadFile(filepath.Join(base, "cert.pem"))
	if err != nil {
		return c, nil, nil, nil, err
	}
	key, _ := os.ReadFile(filepath.Join(base, "key.pem"))
	chain, _ := os.ReadFile(filepath.Join(base, "chain.pem"))
	return c, cert, key, chain, nil
}
func (s *Store) ListCertificates(caID string) ([]domain.Certificate, error) {
	d, err := s.CADir(caID)
	if err != nil {
		return nil, err
	}
	es, err := os.ReadDir(filepath.Join(d, "issued"))
	if err != nil {
		return nil, err
	}
	var out []domain.Certificate
	for _, e := range es {
		if !e.IsDir() || validateSerial(e.Name()) != nil {
			continue
		}
		c, _, _, _, er := s.LoadCertificate(caID, e.Name())
		if er == nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotBefore.Before(out[j].NotBefore) })
	return out, nil
}
func (s *Store) ReadCRL(id string) ([]byte, error) {
	d, e := s.CADir(id)
	if e != nil {
		return nil, e
	}
	return os.ReadFile(filepath.Join(d, "crl/ca.crl.pem"))
}

func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".caforge-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func ParsePositiveDays(s string, def int) (int, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v <= 0 {
		return 0, errors.New("请输入正整数天数")
	}
	return v, nil
}
