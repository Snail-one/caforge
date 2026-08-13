package app

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"caforge/internal/authority"
	"caforge/internal/certificate"
	"caforge/internal/domain"
	"caforge/internal/revocation"
	"caforge/internal/store"
	"caforge/internal/ui"
)

type App struct {
	ui           *ui.Terminal
	repo         Repository
	authorities  AuthorityService
	certificates CertificateService
	revocations  RevocationService
}

type Repository interface {
	Init() error
	CurrentCA() (string, error)
	LoadAuthority(string) (domain.Authority, error)
}

type AuthorityService interface {
	CreateRoot(authority.CreateRootRequest) (domain.Authority, error)
	CreateIntermediate(authority.CreateIntermediateRequest) (domain.Authority, error)
	List() ([]domain.Authority, error)
	Get(string) (domain.Authority, *x509.Certificate, error)
	Select(string) error
}

type CertificateService interface {
	Issue(domain.IssueRequest, []byte) (domain.Certificate, error)
	SignCSR(domain.CSRRequest, []byte) (domain.Certificate, error)
	List(string) ([]domain.Certificate, error)
	Get(string, string) (domain.Certificate, *x509.Certificate, byte, error)
	Renew(string, string, int, []byte, []byte, bool) (domain.Certificate, error)
	Export(string, string, domain.ExportFormat, []byte, []byte) ([]byte, error)
	CertificateChain(string, string) ([]byte, error)
}

type RevocationService interface {
	Revoke(string, string, domain.RevocationReason, []byte) error
	Generate(string, []byte) error
	Read(string) (*x509.RevocationList, error)
}

func New(t *ui.Terminal, repo *store.Store) *App {
	a := authority.New(repo)
	return &App{ui: t, repo: repo, authorities: a, certificates: certificate.New(repo, a), revocations: revocation.New(repo)}
}

func (a *App) Run() error {
	if err := a.repo.Init(); err != nil {
		return err
	}
	for {
		current, _ := a.repo.CurrentCA()
		a.ui.Header("主菜单")
		if current == "" {
			a.ui.Printf("当前 CA：未选择\n\n")
		} else {
			meta, e := a.repo.LoadAuthority(current)
			if e == nil {
				a.ui.Printf("当前 CA：%s (%s)\n\n", meta.Name, meta.ID)
			}
		}
		a.ui.Printf("1. CA 管理\n2. 证书签发\n3. 证书管理\n4. 吊销与 CRL\n\n0/q. 退出\n")
		choice, e := a.ui.Ask("请选择: ")
		if e != nil {
			if errors.Is(e, io.EOF) {
				return nil
			}
			return e
		}
		switch strings.ToLower(choice) {
		case "1":
			e = a.caMenu()
		case "2":
			e = a.issueMenu()
		case "3":
			e = a.certificateMenu()
		case "4":
			e = a.revocationMenu()
		case "0", "q":
			return nil
		default:
			a.ui.Warning("无效选项")
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				return nil
			}
			a.ui.Error(e)
		}
	}
}

func (a *App) caMenu() error {
	for {
		a.ui.Header("主菜单 / CA 管理")
		a.ui.Printf("1. 创建根 CA\n2. 创建中间 CA\n3. CA 列表与详情\n4. 选择当前 CA\n\n0/q. 返回\n")
		v, e := a.ui.Ask("请选择: ")
		if e != nil {
			return e
		}
		switch strings.ToLower(v) {
		case "1":
			e = a.createRoot()
		case "2":
			e = a.createIntermediate()
		case "3":
			e = a.showAuthorities()
		case "4":
			e = a.selectAuthority()
		case "0", "q":
			return nil
		default:
			a.ui.Warning("无效选项")
		}
		if e != nil {
			a.ui.Error(e)
		}
	}
}
func (a *App) createRoot() error {
	a.ui.Header("主菜单 / CA 管理 / 创建根 CA")
	name, e := a.ui.Ask("CA 名称 (0 返回): ")
	if e != nil || ui.IsBack(name) {
		return e
	}
	alg, e := a.chooseAlgorithm(true)
	if e != nil {
		return e
	}
	days, e := a.days("有效天数 [3650]: ", 3650)
	if e != nil {
		return e
	}
	pw, e := a.confirmedPassword("CA 私钥口令: ")
	if e != nil {
		return e
	}
	result, e := a.authorities.CreateRoot(authority.CreateRootRequest{Name: name, Algorithm: alg, Days: days, MaxPathLen: 1, Password: pw})
	if e == nil {
		a.ui.Success(fmt.Sprintf("根 CA 已创建：%s (%s)", result.Name, result.ID))
	}
	return e
}
func (a *App) createIntermediate() error {
	a.ui.Header("主菜单 / CA 管理 / 创建中间 CA")
	parent, e := a.chooseAuthority(true)
	if e != nil || parent == "" {
		return e
	}
	meta, e := a.repo.LoadAuthority(parent)
	if e != nil {
		return e
	}
	if !meta.IsRoot() {
		return errors.New("只能选择根 CA 作为父级")
	}
	name, e := a.ui.Ask("中间 CA 名称: ")
	if e != nil {
		return e
	}
	alg, e := a.chooseAlgorithm(true)
	if e != nil {
		return e
	}
	days, e := a.days("有效天数 [1825]: ", 1825)
	if e != nil {
		return e
	}
	parentPW, e := a.ui.Password("父 CA 私钥口令: ")
	if e != nil {
		return e
	}
	pw, e := a.confirmedPassword("中间 CA 私钥口令: ")
	if e != nil {
		return e
	}
	result, e := a.authorities.CreateIntermediate(authority.CreateIntermediateRequest{ParentID: parent, Name: name, Algorithm: alg, Days: days, ParentPassword: parentPW, Password: pw})
	if e == nil {
		a.ui.Success(fmt.Sprintf("中间 CA 已创建并设为当前：%s (%s)", result.Name, result.ID))
	}
	return e
}
func (a *App) showAuthorities() error {
	a.ui.Header("主菜单 / CA 管理 / CA 列表")
	items, e := a.authorities.List()
	if e != nil {
		return e
	}
	if len(items) == 0 {
		a.ui.Warning("尚未创建 CA")
		return nil
	}
	for i, v := range items {
		kind := "根 CA"
		if !v.IsRoot() {
			kind = "中间 CA"
		}
		a.ui.Printf("%d. %s [%s]  %s  到期 %s\n", i+1, v.Name, kind, v.ID, v.NotAfter.Local().Format("2006-01-02"))
	}
	sel, e := a.ui.Ask("输入编号查看详情，0 返回: ")
	if e != nil || ui.IsBack(sel) {
		return e
	}
	n, e := strconv.Atoi(sel)
	if e != nil || n < 1 || n > len(items) {
		return errors.New("无效编号")
	}
	v, c, e := a.authorities.Get(items[n-1].ID)
	if e != nil {
		return e
	}
	a.ui.Printf("\nID: %s\n名称: %s\n父 CA: %s\n算法: %s\n序列号: %s\n有效期: %s — %s\n路径长度: %d\n", v.ID, v.Name, emptyAs(v.ParentID, "无（自签名）"), v.Algorithm, c.SerialNumber.Text(16), c.NotBefore.Local().Format(time.RFC3339), c.NotAfter.Local().Format(time.RFC3339), v.MaxPathLen)
	_, e = a.ui.Ask("按回车返回...")
	return e
}
func (a *App) selectAuthority() error {
	id, e := a.chooseAuthority(false)
	if e != nil || id == "" {
		return e
	}
	if e = a.authorities.Select(id); e == nil {
		a.ui.Success("当前 CA 已更新")
	}
	return e
}
func (a *App) chooseAuthority(rootOnly bool) (string, error) {
	items, e := a.authorities.List()
	if e != nil {
		return "", e
	}
	filtered := items[:0]
	for _, v := range items {
		if !rootOnly || v.IsRoot() {
			filtered = append(filtered, v)
		}
	}
	if len(filtered) == 0 {
		return "", errors.New("没有可选 CA")
	}
	for i, v := range filtered {
		a.ui.Printf("%d. %s (%s)\n", i+1, v.Name, v.ID)
	}
	v, e := a.ui.Ask("选择编号 (0 返回): ")
	if e != nil || ui.IsBack(v) {
		return "", e
	}
	n, e := strconv.Atoi(v)
	if e != nil || n < 1 || n > len(filtered) {
		return "", errors.New("无效编号")
	}
	return filtered[n-1].ID, nil
}

func (a *App) issueMenu() error {
	ca, e := a.requireCurrent()
	if e != nil {
		return e
	}
	for {
		a.ui.Header("主菜单 / 证书签发")
		a.ui.Printf("当前 CA：%s\n\n1. 生成密钥并签发\n2. 导入 PEM CSR 签发\n\n0/q. 返回\n", ca)
		v, e := a.ui.Ask("请选择: ")
		if e != nil {
			return e
		}
		switch strings.ToLower(v) {
		case "1":
			e = a.issueGenerated(ca)
		case "2":
			e = a.issueCSR(ca)
		case "0", "q":
			return nil
		default:
			a.ui.Warning("无效选项")
		}
		if e != nil {
			a.ui.Error(e)
		}
	}
}
func (a *App) issueGenerated(ca string) error {
	a.ui.Header("主菜单 / 证书签发 / 生成密钥")
	profile, e := a.chooseProfile()
	if e != nil {
		return e
	}
	cn, e := a.ui.Ask("通用名称 CN: ")
	if e != nil {
		return e
	}
	var dns, ips []string
	if profile == domain.Server {
		d, e := a.ui.Ask("DNS SAN（逗号分隔，可空）: ")
		if e != nil {
			return e
		}
		i, e := a.ui.Ask("IP SAN（逗号分隔，可空）: ")
		if e != nil {
			return e
		}
		dns = csv(d)
		ips = csv(i)
		if e = certificate.ValidateSANs(dns, ips); e != nil {
			return e
		}
	}
	alg, e := a.chooseAlgorithm(false)
	if e != nil {
		return e
	}
	days, e := a.days("有效天数 [397]: ", 397)
	if e != nil {
		return e
	}
	encrypt, e := a.ui.Confirm("加密终端私钥？")
	if e != nil {
		return e
	}
	var keyPW []byte
	if encrypt {
		keyPW, e = a.confirmedPassword("终端私钥口令: ")
		if e != nil {
			return e
		}
	} else {
		a.ui.Warning("明文私钥一旦泄露无法通过口令保护")
		ok, e := a.ui.Confirm("确认生成明文私钥？")
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("已取消")
		}
	}
	caPW, e := a.ui.Password("CA 私钥口令: ")
	if e != nil {
		return e
	}
	result, e := a.certificates.Issue(domain.IssueRequest{CAID: ca, CommonName: cn, Profile: profile, Algorithm: alg, DNSNames: dns, IPAddresses: ips, Days: days, EncryptKey: encrypt, KeyPassword: keyPW}, caPW)
	if e == nil {
		a.ui.Success("证书已签发，序列号 " + result.Serial)
	}
	return e
}
func (a *App) issueCSR(ca string) error {
	a.ui.Header("主菜单 / 证书签发 / CSR 签发")
	path, e := a.ui.Ask("CSR PEM 文件路径: ")
	if e != nil {
		return e
	}
	data, e := os.ReadFile(filepath.Clean(path))
	if e != nil {
		return e
	}
	profile, e := a.chooseProfile()
	if e != nil {
		return e
	}
	name, e := a.ui.Ask("覆盖通用名称 CN（留空使用 CSR）: ")
	if e != nil {
		return e
	}
	days, e := a.days("有效天数 [397]: ", 397)
	if e != nil {
		return e
	}
	pw, e := a.ui.Password("CA 私钥口令: ")
	if e != nil {
		return e
	}
	result, e := a.certificates.SignCSR(domain.CSRRequest{CAID: ca, CommonName: name, Profile: profile, CSRPEM: data, Days: days}, pw)
	if e == nil {
		a.ui.Success("CSR 已签发，序列号 " + result.Serial)
	}
	return e
}

func (a *App) certificateMenu() error {
	ca, e := a.requireCurrent()
	if e != nil {
		return e
	}
	filter := ""
	for {
		a.ui.Header("主菜单 / 证书管理")
		items, e := a.certificates.List(ca)
		if e != nil {
			return e
		}
		if filter != "" {
			var matched []domain.Certificate
			needle := strings.ToLower(filter)
			for _, c := range items {
				if strings.Contains(strings.ToLower(c.Serial+" "+c.CommonName+" "+string(c.Profile)), needle) {
					matched = append(matched, c)
				}
			}
			items = matched
			a.ui.Printf("筛选：%s（输入 f 可修改）\n\n", filter)
		}
		if len(items) == 0 && filter == "" {
			a.ui.Warning("当前 CA 尚未签发证书")
			return nil
		}
		if len(items) == 0 {
			a.ui.Warning("没有匹配的证书")
		}
		for i, c := range items {
			_, _, status, _ := a.certificates.Get(ca, c.Serial)
			a.ui.Printf("%d. %s  %s  [%s] %s\n", i+1, c.Serial, c.CommonName, c.Profile, a.ui.Badge(status))
		}
		v, e := a.ui.Ask("选择证书编号，f 筛选，0 返回: ")
		if e != nil {
			return e
		}
		if ui.IsBack(v) {
			return nil
		}
		if strings.EqualFold(v, "f") {
			filter, e = a.ui.Ask("输入序列号/CN/模板（留空清除）: ")
			if e != nil {
				return e
			}
			continue
		}
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > len(items) {
			a.ui.Warning("无效编号")
			continue
		}
		if e = a.certificateActions(ca, items[n-1].Serial); e != nil {
			a.ui.Error(e)
		}
	}
}
func (a *App) certificateActions(ca, serial string) error {
	for {
		meta, cert, status, e := a.certificates.Get(ca, serial)
		if e != nil {
			return e
		}
		a.ui.Header("主菜单 / 证书管理 / " + serial)
		a.ui.Printf("状态: %s\nCN: %s\n模板: %s\n算法: %s\n有效期: %s — %s\nDNS SAN: %s\nIP SAN: %s\n续期来源: %s\n\n1. 查看证书链\n2. 续期（生成新密钥）\n3. 导出 PEM\n4. 导出 PKCS#12\n\n0/q. 返回\n", a.ui.Badge(status), meta.CommonName, meta.Profile, meta.Algorithm, cert.NotBefore.Local().Format(time.RFC3339), cert.NotAfter.Local().Format(time.RFC3339), strings.Join(meta.DNSNames, ", "), strings.Join(meta.IPAddresses, ", "), emptyAs(meta.RenewedFrom, "无"))
		v, e := a.ui.Ask("请选择: ")
		if e != nil {
			return e
		}
		switch strings.ToLower(v) {
		case "1":
			chain, e := a.certificates.CertificateChain(ca, serial)
			if e == nil {
				a.ui.Printf("%s\n", chain)
				_, e = a.ui.Ask("按回车返回...")
			}
		case "2":
			e = a.renew(ca, serial)
		case "3":
			e = a.exportCertificate(ca, serial, domain.ExportPEM)
		case "4":
			e = a.exportCertificate(ca, serial, domain.ExportPKCS12)
		case "0", "q":
			return nil
		default:
			a.ui.Warning("无效选项")
		}
		if e != nil {
			a.ui.Error(e)
		}
	}
}
func (a *App) renew(ca, serial string) error {
	days, e := a.days("新证书有效天数 [397]: ", 397)
	if e != nil {
		return e
	}
	encrypt, e := a.ui.Confirm("加密新私钥？")
	if e != nil {
		return e
	}
	var keyPW []byte
	if encrypt {
		keyPW, e = a.confirmedPassword("新私钥口令: ")
		if e != nil {
			return e
		}
	} else {
		a.ui.Warning("将生成明文私钥")
		ok, e := a.ui.Confirm("确认？")
		if e != nil || !ok {
			return e
		}
	}
	caPW, e := a.ui.Password("CA 私钥口令: ")
	if e != nil {
		return e
	}
	result, e := a.certificates.Renew(ca, serial, days, caPW, keyPW, encrypt)
	if e == nil {
		a.ui.Success("续期完成，新序列号 " + result.Serial + "；旧证书未吊销")
	}
	return e
}
func (a *App) exportCertificate(ca, serial string, format domain.ExportFormat) error {
	var keyPW, exportPW []byte
	if format == domain.ExportPKCS12 {
		keyPW, _ = a.ui.Password("证书私钥口令（明文私钥留空）: ")
		var e error
		exportPW, e = a.confirmedPassword("PKCS#12 导出口令: ")
		if e != nil {
			return e
		}
	}
	data, e := a.certificates.Export(ca, serial, format, keyPW, exportPW)
	if e != nil {
		return e
	}
	def := serial + "." + string(format)
	if format == domain.ExportPKCS12 {
		def = serial + ".p12"
	}
	path, e := a.ui.Ask("输出路径 [" + def + "]: ")
	if e != nil {
		return e
	}
	if path == "" {
		path = def
	}
	if _, e = os.Stat(path); e == nil {
		ok, er := a.ui.Confirm("文件已存在，覆盖？")
		if er != nil {
			return er
		}
		if !ok {
			return errors.New("已取消")
		}
	}
	if e = os.WriteFile(filepath.Clean(path), data, 0600); e == nil {
		e = os.Chmod(filepath.Clean(path), 0600)
	}
	if e == nil {
		a.ui.Success("已导出到 " + path)
	}
	return e
}

func (a *App) revocationMenu() error {
	ca, e := a.requireCurrent()
	if e != nil {
		return e
	}
	for {
		a.ui.Header("主菜单 / 吊销与 CRL")
		a.ui.Printf("1. 吊销证书\n2. 查看 CRL\n3. 重新生成 CRL\n\n0/q. 返回\n")
		v, e := a.ui.Ask("请选择: ")
		if e != nil {
			return e
		}
		switch strings.ToLower(v) {
		case "1":
			e = a.revoke(ca)
		case "2":
			crl, er := a.revocations.Read(ca)
			e = er
			if er == nil {
				a.ui.Printf("编号: %s\nthisUpdate: %s\nnextUpdate: %s\n吊销条目: %d\n", crl.Number, crl.ThisUpdate.Local().Format(time.RFC3339), crl.NextUpdate.Local().Format(time.RFC3339), len(crl.RevokedCertificateEntries))
				_, e = a.ui.Ask("按回车返回...")
			}
		case "3":
			pw, er := a.ui.Password("CA 私钥口令: ")
			e = er
			if er == nil {
				e = a.revocations.Generate(ca, pw)
				if e == nil {
					a.ui.Success("CRL 已重新生成")
				}
			}
		case "0", "q":
			return nil
		default:
			a.ui.Warning("无效选项")
		}
		if e != nil {
			a.ui.Error(e)
		}
	}
}
func (a *App) revoke(ca string) error {
	items, e := a.certificates.List(ca)
	if e != nil {
		return e
	}
	for i, c := range items {
		_, _, status, _ := a.certificates.Get(ca, c.Serial)
		a.ui.Printf("%d. %s %s %s\n", i+1, c.Serial, c.CommonName, a.ui.Badge(status))
	}
	v, e := a.ui.Ask("选择编号 (0 返回): ")
	if e != nil || ui.IsBack(v) {
		return e
	}
	n, e := strconv.Atoi(v)
	if e != nil || n < 1 || n > len(items) {
		return errors.New("无效编号")
	}
	serial := items[n-1].Serial
	reasons := revocation.Reasons()
	for i, r := range reasons {
		a.ui.Printf("%d. %s\n", i+1, r.Label)
	}
	rv, e := a.ui.Ask("吊销原因: ")
	if e != nil {
		return e
	}
	ri, e := strconv.Atoi(rv)
	if e != nil || ri < 1 || ri > len(reasons) {
		return errors.New("无效原因")
	}
	confirm, e := a.ui.Ask("吊销不可撤销。请输入“吊销 " + serial + "”确认: ")
	if e != nil {
		return e
	}
	if confirm != "吊销 "+serial {
		return errors.New("确认文字不匹配，已取消")
	}
	pw, e := a.ui.Password("CA 私钥口令: ")
	if e != nil {
		return e
	}
	if e = a.revocations.Revoke(ca, serial, reasons[ri-1].Value, pw); e == nil {
		a.ui.Success("证书已吊销，PEM/DER CRL 已更新")
	}
	return e
}

func (a *App) requireCurrent() (string, error) {
	id, e := a.repo.CurrentCA()
	if e != nil {
		return "", e
	}
	if id == "" {
		return "", errors.New("请先创建或选择当前 CA")
	}
	return id, nil
}
func (a *App) chooseProfile() (domain.Profile, error) {
	v, e := a.ui.Ask("模板：1. 服务器  2. 客户端  (0 返回): ")
	if e != nil {
		return "", e
	}
	switch v {
	case "1":
		return domain.Server, nil
	case "2":
		return domain.Client, nil
	case "0", "q":
		return "", errors.New("已取消")
	default:
		return "", errors.New("无效模板")
	}
}
func (a *App) chooseAlgorithm(ca bool) (domain.Algorithm, error) {
	if ca {
		v, e := a.ui.Ask("算法：1. ECDSA P-384 [默认]  2. RSA-3072  3. RSA-4096: ")
		if e != nil {
			return "", e
		}
		switch v {
		case "", "1":
			return domain.ECDSAP384, nil
		case "2":
			return domain.RSA3072, nil
		case "3":
			return domain.RSA4096, nil
		default:
			return "", errors.New("无效算法")
		}
	}
	v, e := a.ui.Ask("算法：1. ECDSA P-256 [默认]  2. RSA-3072: ")
	if e != nil {
		return "", e
	}
	if v == "" || v == "1" {
		return domain.ECDSAP256, nil
	}
	if v == "2" {
		return domain.RSA3072, nil
	}
	return "", errors.New("无效算法")
}
func (a *App) days(prompt string, def int) (int, error) {
	v, e := a.ui.Ask(prompt)
	if e != nil {
		return 0, e
	}
	return store.ParsePositiveDays(v, def)
}
func (a *App) confirmedPassword(prompt string) ([]byte, error) {
	first, e := a.ui.Password(prompt)
	if e != nil {
		return nil, e
	}
	if len(first) == 0 {
		return nil, errors.New("口令不能为空")
	}
	second, e := a.ui.Password("再次输入口令: ")
	if e != nil {
		return nil, e
	}
	if string(first) != string(second) {
		return nil, errors.New("两次口令不一致")
	}
	return first, nil
}
func csv(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
func emptyAs(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
