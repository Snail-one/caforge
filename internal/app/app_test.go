package app

import (
	"bytes"
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"caforge/internal/authority"
	"caforge/internal/certificate"
	"caforge/internal/domain"
	"caforge/internal/store"
	"caforge/internal/ui"
	"caforge/internal/version"
)

func TestScriptedMenuCreatesRootAndExits(t *testing.T) {
	previousVersion := version.Version
	version.Version = "v9.8.7"
	t.Cleanup(func() { version.Version = previousVersion })
	// Main/CA/Create root, accept default algorithm and validity, confirm password,
	// return from CA menu, then exit the application.
	in := strings.NewReader("1\n1\n测试根\n\n\nsecret\nsecret\n0\n0\n")
	var out bytes.Buffer
	repo, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = New(ui.New(in, &out, false, nil), repo).Run(); err != nil {
		t.Fatal(err)
	}
	items, err := repo.ListAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "测试根" {
		t.Fatalf("authorities: %#v", items)
	}
	if !strings.Contains(out.String(), "根 CA 创建完成") {
		t.Fatalf("missing success output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "版本 v9.8.7") {
		t.Fatalf("主菜单缺少版本徽标：\n%s", out.String())
	}
	for _, want := range []string{"创建、查看和选择签发机构", "生成密钥签发或导入 CSR", "查询、续期和导出证书", "查看或重新生成证书吊销列表"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("主菜单缺少用途说明 %q：\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("non-color UI emitted ANSI")
	}
}

type exportCertificateService struct {
	data      []byte
	materials certificate.DeploymentMaterials
	meta      domain.Certificate
	parsed    *x509.Certificate
	paths     certificate.FilePaths
	items     []domain.Certificate
}

type captureRevocationService struct {
	calls  int
	ca     string
	serial string
	reason domain.RevocationReason
}

func (s *captureRevocationService) Revoke(ca, serial string, reason domain.RevocationReason, _ []byte) error {
	s.calls++
	s.ca = ca
	s.serial = serial
	s.reason = reason
	return nil
}
func (s *captureRevocationService) Generate(string, []byte) error { return nil }
func (s *captureRevocationService) Read(string) (*x509.RevocationList, error) {
	return &x509.RevocationList{}, nil
}

func (s exportCertificateService) Issue(domain.IssueRequest, []byte) (domain.Certificate, error) {
	return domain.Certificate{}, nil
}
func (s exportCertificateService) SignCSR(domain.CSRRequest, []byte) (domain.Certificate, error) {
	return domain.Certificate{}, nil
}
func (s exportCertificateService) List(caID string) ([]domain.Certificate, error) {
	if len(s.items) == 0 {
		return nil, nil
	}
	var out []domain.Certificate
	for _, item := range s.items {
		if caID == "" || item.CAID == "" || item.CAID == caID {
			out = append(out, item)
		}
	}
	return out, nil
}
func (s exportCertificateService) Get(string, string) (domain.Certificate, *x509.Certificate, byte, error) {
	return s.meta, s.parsed, 'V', nil
}
func (s exportCertificateService) Renew(string, string, int, []byte, []byte, bool) (domain.Certificate, error) {
	return domain.Certificate{}, nil
}
func (s exportCertificateService) Export(string, string, domain.ExportFormat, []byte, []byte) ([]byte, error) {
	return s.data, nil
}
func (s exportCertificateService) FilePaths(string, string) (certificate.FilePaths, error) {
	return s.paths, nil
}
func (s exportCertificateService) DeploymentMaterials(string, string) (certificate.DeploymentMaterials, error) {
	return s.materials, nil
}

func TestCertificateDetailsDisplayAbsoluteFilePaths(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "cas", "test-ca", "issued", "1000")
	paths := certificate.FilePaths{
		Directory:   base,
		Certificate: filepath.Join(base, "cert.pem"),
		PrivateKey:  filepath.Join(base, "key.pem"),
		Chain:       filepath.Join(base, "chain.pem"),
	}
	now := time.Now()
	service := exportCertificateService{
		meta: domain.Certificate{Serial: "1000", CommonName: "fwq", Profile: domain.Server, HasKey: true},
		parsed: &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.AddDate(1, 0, 0),
		},
		paths: paths,
	}
	var out bytes.Buffer
	a := &App{
		ui:           ui.New(strings.NewReader("0\n"), &out, false, nil),
		repo:         currentCARepository{items: []domain.Authority{{ID: "test-ca", Name: "测试签发", ParentID: "root-ca"}}},
		certificates: service,
	}
	if err := a.certificateActions("test-ca", "1000"); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	if !strings.Contains(got, "签发 CA：测试签发（test-ca）") {
		t.Fatalf("证书详情缺少签发 CA：\n%s", got)
	}
	for label, path := range map[string]string{
		"记录目录":  base,
		"证书文件":  paths.Certificate,
		"完整证书链": paths.Chain,
		"私钥文件":  paths.PrivateKey,
	} {
		if !strings.Contains(got, label+"："+path) {
			t.Fatalf("证书详情缺少 %s 的绝对路径 %q：\n%s", label, path, got)
		}
	}
	for _, want := range []string{"查看证书", "显示私钥、部署用完整链和根 CA", "吊销证书", "必须再次确认", "部署说明"} {
		if !strings.Contains(got, want) {
			t.Fatalf("证书操作菜单缺少 %q：\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"查看证书链", "查看并复制部署文件"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("证书操作菜单仍包含旧选项 %q：\n%s", unwanted, got)
		}
	}
}

func TestRevokeCertificateRequiresYOrYesConfirmation(t *testing.T) {
	for _, confirmation := range []string{"y", "yes", "Y", "YES"} {
		t.Run(confirmation, func(t *testing.T) {
			var out bytes.Buffer
			service := &captureRevocationService{}
			a := &App{
				ui:          ui.New(strings.NewReader("1\n"+confirmation+"\nsecret\n\n"), &out, false, nil),
				revocations: service,
			}
			certificate := domain.Certificate{Serial: "1000", CommonName: "server.test"}
			if err := a.revokeCertificate("issuing-ca", certificate); err != nil {
				t.Fatal(err)
			}
			if service.calls != 1 || service.ca != "issuing-ca" || service.serial != "1000" {
				t.Fatalf("unexpected revoke call: %#v", service)
			}
			got := out.String()
			for _, want := range []string{"吊销证书", "确认永久吊销", "请输入 y 或 yes", "证书已吊销"} {
				if !strings.Contains(got, want) {
					t.Fatalf("吊销确认界面缺少 %q：\n%s", want, got)
				}
			}
		})
	}
}

func TestRevokeCertificateRejectsOtherConfirmation(t *testing.T) {
	for _, confirmation := range []string{"", "n", "是", "吊销 1000", "1"} {
		t.Run("input_"+confirmation, func(t *testing.T) {
			var out bytes.Buffer
			service := &captureRevocationService{}
			a := &App{
				ui:          ui.New(strings.NewReader("1\n"+confirmation+"\n"), &out, false, nil),
				revocations: service,
			}
			err := a.revokeCertificate("issuing-ca", domain.Certificate{Serial: "1000", CommonName: "server.test"})
			if !errors.Is(err, errCancelled) {
				t.Fatalf("err=%v, want errCancelled", err)
			}
			if service.calls != 0 {
				t.Fatalf("confirmation %q unexpectedly revoked certificate", confirmation)
			}
			if !strings.Contains(out.String(), "未输入 y 或 yes，证书未吊销") {
				t.Fatalf("缺少取消提示：\n%s", out.String())
			}
		})
	}
}

type currentCARepository struct {
	Repository
	current string
	items   []domain.Authority
}

func (r currentCARepository) CurrentCA() (string, error) { return r.current, nil }
func (r currentCARepository) LoadAuthority(id string) (domain.Authority, error) {
	for _, item := range r.items {
		if item.ID == id {
			return item, nil
		}
	}
	return domain.Authority{}, errors.New("未找到 CA")
}

type authorityListService struct {
	AuthorityService
	items       []domain.Authority
	certificate *x509.Certificate
	materials   authority.PublicMaterials
	status      string
}

func (s authorityListService) List() ([]domain.Authority, error) { return s.items, nil }
func (s authorityListService) Status(string) (string, error) {
	if s.status == "" {
		return "可用", nil
	}
	return s.status, nil
}
func (s authorityListService) SetDisabled(string, bool) error { return nil }
func (s authorityListService) Delete(string) error            { return nil }
func (s authorityListService) PublicMaterials(string) (authority.PublicMaterials, error) {
	return s.materials, nil
}
func (s authorityListService) Get(id string) (domain.Authority, *x509.Certificate, error) {
	for _, item := range s.items {
		if item.ID == id {
			return item, s.certificate, nil
		}
	}
	return domain.Authority{}, nil, errors.New("authority not found")
}
func (s authorityListService) Select(string) error { return nil }

func TestChooseAuthorityDisplaysAndMarksCurrentCA(t *testing.T) {
	items := []domain.Authority{
		{ID: "joker-536f4a6c", Name: "joker"},
		{ID: "joker-one-3ac2f408", Name: "joker-one"},
	}
	var out bytes.Buffer
	a := &App{
		ui:          ui.New(strings.NewReader("1\n"), &out, false, nil),
		repo:        currentCARepository{current: items[1].ID},
		authorities: authorityListService{items: items},
	}
	selected, err := a.chooseAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	if selected != items[0].ID {
		t.Fatalf("selected=%q, want %q", selected, items[0].ID)
	}

	got := out.String()
	for _, want := range []string{"当前选择", "名称：joker-one", "CA ID：joker-one-3ac2f408", "[当前]", "joker-one-3ac2f408"} {
		if !strings.Contains(got, want) {
			t.Fatalf("CA 选择界面缺少 %q：\n%s", want, got)
		}
	}
}

func TestChooseAuthorityDisplaysIntermediateTree(t *testing.T) {
	items := []domain.Authority{
		{ID: "fca-02-int", Name: "FCA-02-INT", ParentID: "fca-02-498"},
		{ID: "ca-2073af77", Name: "测试"},
		{ID: "01-2eb5054f", Name: "测试-01"},
		{ID: "fca-02-498", Name: "FCA-02"},
		{ID: "fca-02-int-2", Name: "FCA-02-INT-2", ParentID: "fca-02-498"},
	}
	var out bytes.Buffer
	a := &App{
		ui:          ui.New(strings.NewReader("4\n"), &out, false, nil),
		repo:        currentCARepository{current: "ca-2073af77"},
		authorities: authorityListService{items: items},
	}
	selected, err := a.chooseAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	if selected != "fca-02-int" {
		t.Fatalf("selected=%q, want fca-02-int", selected)
	}

	got := out.String()
	for _, want := range []string{
		"测试", "[当前]", "ca-2073af77",
		"测试-01", "01-2eb5054f",
		"FCA-02", "fca-02-498",
		"├─ 4", "FCA-02-INT", "fca-02-int",
		"└─ 5", "FCA-02-INT-2", "fca-02-int-2",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("签发 CA 树状列表缺少 %q：\n%s", want, got)
		}
	}
	if strings.Index(got, "FCA-02") > strings.Index(got, "├─ 4") {
		t.Fatalf("中间 CA 应挂在父根 CA 下方：\n%s", got)
	}
	var rootHintCols []int
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if strings.HasPrefix(trimmed, "├") || strings.HasPrefix(trimmed, "└") {
			continue
		}
		if col := strings.Index(line, "-- "); col >= 0 {
			rootHintCols = append(rootHintCols, displayColumn(line[:col]))
		}
	}
	if len(rootHintCols) != 3 {
		t.Fatalf("签发 CA 根行 hint 列数=%d，want 3：\n%s", len(rootHintCols), got)
	}
	for _, col := range rootHintCols[1:] {
		if col != rootHintCols[0] {
			t.Fatalf("未选中的根 CA 与当前根 CA 的 -- 列未对齐：\n%s", got)
		}
	}
}

func TestSelectSigningAuthorityUsesSeparatePage(t *testing.T) {
	items := []domain.Authority{{ID: "joker-one", Name: "joker-one"}}
	var out bytes.Buffer
	a := &App{
		ui:          ui.New(strings.NewReader("1\n\n"), &out, false, nil),
		repo:        currentCARepository{current: "joker-one"},
		authorities: authorityListService{items: items},
	}
	if err := a.selectAuthority(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"CAForge  ›  证书签发  ›  选择签发 CA", "当前选择", "当前签发 CA 已更新"} {
		if !strings.Contains(got, want) {
			t.Fatalf("选择签发 CA 独立页面缺少 %q：\n%s", want, got)
		}
	}
}

func TestChooseRootDisplaysExistingIntermediateCount(t *testing.T) {
	items := []domain.Authority{
		{ID: "root-one", Name: "根一"},
		{ID: "root-two", Name: "根二"},
		{ID: "issuing-one", Name: "签发一", ParentID: "root-one"},
		{ID: "issuing-two", Name: "签发二", ParentID: "root-one"},
	}
	var out bytes.Buffer
	a := &App{
		ui:          ui.New(strings.NewReader("1\n"), &out, false, nil),
		authorities: authorityListService{items: items},
	}
	selected, err := a.chooseAuthority(true)
	if err != nil {
		t.Fatal(err)
	}
	if selected != "root-one" {
		t.Fatalf("selected=%q, want root-one", selected)
	}

	got := out.String()
	for _, want := range []string{
		"root-one · 已有 2 个中间 CA",
		"root-two · 已有 0 个中间 CA",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("根 CA 选择界面缺少 %q：\n%s", want, got)
		}
	}
}

func TestAuthorityListShowsWhichRootIssuedIntermediate(t *testing.T) {
	now := time.Now()
	items := []domain.Authority{
		{ID: "joker-536f4a6c", Name: "joker", NotAfter: now.AddDate(10, 0, 0)},
		{ID: "joker-one-3ac2f408", Name: "joker-one", ParentID: "joker-536f4a6c", NotAfter: now.AddDate(5, 0, 0)},
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(4096),
		NotBefore:    now,
		NotAfter:     now.AddDate(5, 0, 0),
	}
	var out bytes.Buffer
	a := &App{
		ui:           ui.New(strings.NewReader("2\n0\n"), &out, false, nil),
		authorities:  authorityListService{items: items, certificate: certificate},
		certificates: exportCertificateService{},
	}
	if err := a.showAuthorities(); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{
		"joker-536f4a6c · 自签名",
		"└─ 2", "joker-one", "[中间 CA]", "joker-one-3ac2f408",
		"证书链层级：joker（根 CA） → joker-one（中间 CA）",
		"父 CA：joker（joker-536f4a6c）",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CA 层级显示缺少 %q：\n%s", want, got)
		}
	}
	if strings.Contains(got, "[当前]") {
		t.Fatalf("CA 层级列表不应显示当前标记：\n%s", got)
	}
}

func TestAuthorityCertificateViewsOnlyPublicPEM(t *testing.T) {
	materials := authority.PublicMaterials{
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n"),
		ChainPEM: []byte("-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n" +
			"-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n"),
		RootCAPEM: []byte("-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n"),
	}
	meta := domain.Authority{ID: "issuing-ca", Name: "Issuing CA", ParentID: "root-ca"}
	for _, fullChain := range []bool{false, true} {
		var out bytes.Buffer
		a := &App{
			ui:          ui.New(strings.NewReader("\n"), &out, false, nil),
			authorities: authorityListService{materials: materials},
		}
		if err := a.showAuthorityCertificate(meta, fullChain); err != nil {
			t.Fatal(err)
		}
		got := out.String()
		if !strings.Contains(got, "INTERMEDIATE") || strings.Contains(got, "PRIVATE KEY") {
			t.Fatalf("CA 公开证书显示异常：\n%s", got)
		}
		if fullChain && (!strings.Contains(got, "当前 CA → 根 CA") || !strings.Contains(got, "ROOT")) {
			t.Fatalf("完整 CA 链显示异常：\n%s", got)
		}
	}
}

func TestRevokeIntermediateUsesParentRootAndStrictConfirmation(t *testing.T) {
	root := domain.Authority{ID: "root-ca", Name: "Root CA"}
	intermediate := domain.Authority{ID: "issuing-ca", Name: "Issuing CA", ParentID: root.ID, IssuerSerial: "1000"}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(4096), NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0)}
	for _, test := range []struct {
		name         string
		confirmation string
		wantCalls    int
	}{
		{name: "yes", confirmation: "yes", wantCalls: 1},
		{name: "reject chinese yes", confirmation: "是", wantCalls: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			revocations := &captureRevocationService{}
			input := "3\n" + test.confirmation + "\n"
			if test.wantCalls == 1 {
				input += "root-secret\n\n"
			}
			a := &App{
				ui:          ui.New(strings.NewReader(input), &out, false, nil),
				authorities: authorityListService{items: []domain.Authority{root, intermediate}, certificate: certificate},
				revocations: revocations,
			}
			err := a.revokeIntermediate(intermediate, 4)
			if test.wantCalls == 0 && !errors.Is(err, errCancelled) {
				t.Fatalf("err=%v, want cancellation", err)
			}
			if test.wantCalls == 1 && err != nil {
				t.Fatal(err)
			}
			if revocations.calls != test.wantCalls {
				t.Fatalf("revoke calls=%d, want %d", revocations.calls, test.wantCalls)
			}
			if test.wantCalls == 1 && (revocations.ca != root.ID || revocations.serial != intermediate.IssuerSerial || revocations.reason != domain.CACompromise) {
				t.Fatalf("unexpected revoke call: %#v", revocations)
			}
			got := out.String()
			for _, want := range []string{"父根 CA：Root CA（root-ca）", "已有 4 条签发记录", "父根 CA 的 PEM/DER CRL"} {
				if !strings.Contains(got, want) {
					t.Fatalf("中间 CA 吊销界面缺少 %q：\n%s", want, got)
				}
			}
		})
	}
}

func TestCertificateMenuGroupsCertificatesByIssuer(t *testing.T) {
	root := domain.Authority{ID: "joker-536f4a6c", Name: "joker"}
	issuer := domain.Authority{ID: "joker-one-3ac2f408", Name: "joker-one", ParentID: root.ID}
	var out bytes.Buffer
	a := &App{
		ui: ui.New(strings.NewReader("0\n"), &out, false, nil),
		repo: currentCARepository{
			current: issuer.ID,
			items:   []domain.Authority{root, issuer},
		},
		authorities: authorityListService{items: []domain.Authority{root, issuer}},
		certificates: exportCertificateService{
			items: []domain.Certificate{
				{Serial: "1000", CommonName: "fwq", Profile: domain.Server, CAID: issuer.ID},
				{Serial: "1001", CommonName: "khd", Profile: domain.Client, CAID: issuer.ID},
			},
		},
	}
	if err := a.certificateMenu(); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{
		"joker  ›  joker-one",
		"fwq",
		"khd",
		"筛选证书",
		"选择证书编号，f 筛选，0 返回",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("证书管理缺少 %q：\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"[根 CA]", "└─", "├─", "选择签发 CA", "当前签发机构", "s 切换签发 CA"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("证书管理不应再显示 %q：\n%s", unwanted, got)
		}
	}
}

func TestCertificateMenuDisplaysCertificatesUnderIssuerTree(t *testing.T) {
	root := domain.Authority{ID: "ca-2073af77", Name: "测试"}
	intermediate := domain.Authority{ID: "01-2eb5054f", Name: "测试-01", ParentID: root.ID}
	other := domain.Authority{ID: "fca-02-498", Name: "FCA-02"}
	otherInt := domain.Authority{ID: "fca-02-zj-01-7010d477", Name: "FCA-02-ZJ-01", ParentID: other.ID}
	items := []domain.Authority{root, intermediate, other, otherInt}
	var out bytes.Buffer
	a := &App{
		ui:          ui.New(strings.NewReader("0\n"), &out, false, nil),
		repo:        currentCARepository{current: intermediate.ID, items: items},
		authorities: authorityListService{items: items},
		certificates: exportCertificateService{
			items: []domain.Certificate{
				{Serial: "1000", CommonName: "fwq", Profile: domain.Server, CAID: intermediate.ID},
				{Serial: "1000", CommonName: "测试-01", Profile: domain.Intermediate, CAID: root.ID},
				{Serial: "1000", CommonName: "OF-01-FWQ", Profile: domain.Client, CAID: otherInt.ID},
			},
		},
	}
	if err := a.certificateMenu(); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{
		"测试  ›  测试-01",
		"1", "fwq", "1000 · server",
		"FCA-02  ›  FCA-02-ZJ-01",
		"2", "OF-01-FWQ", "1000 · client",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("证书管理分组列表缺少 %q：\n%s", want, got)
		}
	}
	if strings.Index(got, "测试  ›  测试-01") > strings.Index(got, "fwq") {
		t.Fatalf("证书应列在签发路径下方：\n%s", got)
	}
	for _, unwanted := range []string{"[根 CA]", "intermediate-ca", "└─", "ca-2073af77"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("证书管理不应显示 %q：\n%s", unwanted, got)
		}
	}
}

func TestIssueMenuContainsSigningCASelection(t *testing.T) {
	var out bytes.Buffer
	a := &App{
		ui:   ui.New(strings.NewReader("0\n"), &out, false, nil),
		repo: currentCARepository{},
	}
	if err := a.issueMenu(); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{"当前签发机构", "[未选择]", "选择签发 CA", "先选择签发 CA", "生成密钥并签发", "导入 PEM CSR 签发"} {
		if !strings.Contains(got, want) {
			t.Fatalf("证书签发菜单缺少 %q：\n%s", want, got)
		}
	}
	if !(strings.Index(got, "选择签发 CA") < strings.Index(got, "生成密钥并签发") && strings.Index(got, "生成密钥并签发") < strings.Index(got, "导入 PEM CSR 签发")) {
		t.Fatalf("证书签发菜单顺序不正确：\n%s", got)
	}
}

func TestExportDisplaysAbsolutePath(t *testing.T) {
	workingDir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(workingDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	var out bytes.Buffer
	view := ui.New(strings.NewReader("\n\n"), &out, false, nil)
	a := &App{ui: view, certificates: exportCertificateService{data: []byte("certificate")}}
	if err = a.exportCertificate("ca", "1000", domain.ExportPEM); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(workingDir, "1000.pem")
	if !strings.Contains(out.String(), "文件："+want) {
		t.Fatalf("成功卡片未显示绝对路径 %q：\n%s", want, out.String())
	}
	if data, readErr := os.ReadFile(want); readErr != nil || string(data) != "certificate" {
		t.Fatalf("导出文件错误：data=%q err=%v", data, readErr)
	}
}

func TestPKCS12ExportDisplaysAbsolutePath(t *testing.T) {
	workingDir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(workingDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	var out bytes.Buffer
	// Private-key password (empty), export password twice, default path, pause.
	view := ui.New(strings.NewReader("\nexport-secret\nexport-secret\n\n\n"), &out, false, nil)
	a := &App{ui: view, certificates: exportCertificateService{data: []byte("pkcs12")}}
	if err = a.exportCertificate("ca", "1001", domain.ExportPKCS12); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(workingDir, "1001.p12")
	if !strings.Contains(out.String(), "文件："+want) {
		t.Fatalf("成功卡片未显示 PKCS#12 绝对路径 %q：\n%s", want, out.String())
	}
	if data, readErr := os.ReadFile(want); readErr != nil || string(data) != "pkcs12" {
		t.Fatalf("PKCS#12 导出文件错误：data=%q err=%v", data, readErr)
	}
}

func TestCertificateUsageExplainsServerDeployment(t *testing.T) {
	var out bytes.Buffer
	a := &App{ui: ui.New(strings.NewReader(""), &out, false, nil)}
	a.showCertificateUsage(domain.Certificate{
		Serial: "1000", CommonName: "server.test", Profile: domain.Server, HasKey: true,
	})

	got := out.String()
	for _, want := range []string{
		"服务器部署所需文件", "server.fullchain.pem", "服务器证书 → 中间 CA 证书",
		"根 CA 通常不放入服务器 fullchain", "server.key.pem", "客户端信任库",
		"安装根 CA 证书", "不应直接作为 Nginx ssl_certificate",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("服务器部署说明缺少 %q：\n%s", want, got)
		}
	}
}

func TestCertificateUsageExplainsCSRClientKeyOwnership(t *testing.T) {
	var out bytes.Buffer
	a := &App{ui: ui.New(strings.NewReader(""), &out, false, nil)}
	a.showCertificateUsage(domain.Certificate{
		Serial: "1001", CommonName: "client", Profile: domain.Client, HasKey: false,
	})

	got := out.String()
	for _, want := range []string{"客户端证书使用方式", "生成 CSR 时保留的原始客户端私钥", "PKCS#12", "启用 mTLS"} {
		if !strings.Contains(got, want) {
			t.Fatalf("客户端使用说明缺少 %q：\n%s", want, got)
		}
	}
}

func TestCopyableServerFilesShowEveryDeploymentMaterial(t *testing.T) {
	materials := certificate.DeploymentMaterials{
		CertificatePEM:       []byte("-----BEGIN CERTIFICATE-----\nSERVER\n-----END CERTIFICATE-----\n"),
		PrivateKeyPEM:        []byte("-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n"),
		FullChainPEM:         []byte("SERVER-FULLCHAIN\n"),
		CompleteChainPEM:     []byte("COMPLETE-CHAIN\n"),
		IntermediateChainPEM: []byte("INTERMEDIATE-CA\n"),
		RootCAPEM:            []byte("ROOT-CA\n"),
	}
	var out bytes.Buffer
	a := &App{
		ui:           ui.New(strings.NewReader("y\n"), &out, false, nil),
		certificates: exportCertificateService{materials: materials},
	}
	meta := domain.Certificate{Serial: "1000", CommonName: "server.test", Profile: domain.Server, HasKey: true}
	if err := a.showCopyableCertificateFiles("ca", "1000", meta); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{
		"包含私钥", "[1] 私钥（敏感）", "server.key.pem",
		"[2] 部署用完整链", "server.fullchain.pem",
		"[3] 根 CA 证书（信任锚）", "root-ca.pem",
		"客户端安装证书 CA", "Nginx ssl_certificate", "0600",
		"SECRET", "SERVER-FULLCHAIN", "ROOT-CA",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("可复制部署文件缺少 %q：\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"server.cert.pem", "intermediate-ca.pem", "complete-chain.pem", "[4]", "[5]", "[6]"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("精简后的可复制部署文件不应包含 %q：\n%s", unwanted, got)
		}
	}
}

func TestCopyableCSRFilesExplainMissingPrivateKey(t *testing.T) {
	materials := certificate.DeploymentMaterials{
		CertificatePEM:   []byte("CLIENT-CERT\n"),
		FullChainPEM:     []byte("CLIENT-CHAIN\n"),
		CompleteChainPEM: []byte("COMPLETE-CHAIN\n"),
		RootCAPEM:        []byte("ROOT-CA\n"),
	}
	var out bytes.Buffer
	a := &App{
		ui:           ui.New(strings.NewReader("y\n"), &out, false, nil),
		certificates: exportCertificateService{materials: materials},
	}
	meta := domain.Certificate{Serial: "1001", CommonName: "client", Profile: domain.Client, HasKey: false}
	if err := a.showCopyableCertificateFiles("ca", "1001", meta); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{"client.key.pem", "client.fullchain.pem", "私钥未显示", "外部 CSR", "mTLS 服务器信任的根 CA"} {
		if !strings.Contains(got, want) {
			t.Fatalf("CSR 可复制文件说明缺少 %q：\n%s", want, got)
		}
	}
	if strings.Contains(got, "BEGIN PRIVATE KEY") {
		t.Fatalf("CSR 记录不应显示私钥：\n%s", got)
	}
}

func TestFormInputsRetryInPlace(t *testing.T) {
	// Empty required value, invalid/out-of-range index, invalid days, then valid values.
	var out bytes.Buffer
	view := ui.New(strings.NewReader("\n有效名称\nabc\n9\n2\nnope\n-1\n30\n"), &out, false, nil)
	a := &App{ui: view}

	name, err := a.askRequired("名称: ", true)
	if err != nil || name != "有效名称" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	index, err := a.askIndex("编号: ", 3)
	if err != nil || index != 2 {
		t.Fatalf("index=%d err=%v", index, err)
	}
	days, err := a.days("天数 [397]: ", 397)
	if err != nil || days != 30 {
		t.Fatalf("days=%d err=%v", days, err)
	}

	got := out.String()
	for _, want := range []string{"此项不能为空", "1 到 3", "请输入正整数天数"} {
		if !strings.Contains(got, want) {
			t.Fatalf("重试提示缺少 %q：\n%s", want, got)
		}
	}
}

func TestChoicesAndPasswordRetryInPlace(t *testing.T) {
	var out bytes.Buffer
	view := ui.New(strings.NewReader("bad\n2\n9\n1\n\nsecret\nwrong\nsecret\nsecret\n"), &out, false, nil)
	a := &App{ui: view}

	profile, err := a.chooseProfile()
	if err != nil || profile != domain.Client {
		t.Fatalf("profile=%q err=%v", profile, err)
	}
	algorithm, err := a.chooseAlgorithm(false)
	if err != nil || algorithm != domain.ECDSAP256 {
		t.Fatalf("algorithm=%q err=%v", algorithm, err)
	}
	password, err := a.confirmedPassword("口令: ")
	if err != nil || string(password) != "secret" {
		t.Fatalf("password=%q err=%v", password, err)
	}

	got := out.String()
	if strings.Count(got, "无效选项") < 2 {
		t.Fatalf("选项未就地重试：\n%s", got)
	}
	for _, want := range []string{"口令不能为空", "两次口令不一致"} {
		if !strings.Contains(got, want) {
			t.Fatalf("口令重试提示缺少 %q：\n%s", want, got)
		}
	}
}

func displayColumn(text string) int {
	width := 0
	for _, current := range text {
		if current >= 0x2e80 {
			width += 2
		} else {
			width++
		}
	}
	return width
}
