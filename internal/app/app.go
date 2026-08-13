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
	"caforge/internal/version"
)

type App struct {
	ui           *ui.Terminal
	repo         Repository
	authorities  AuthorityService
	certificates CertificateService
	revocations  RevocationService
}

var errCancelled = errors.New("已取消")

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
		a.ui.HomeHeader(version.Version)
		authorities, _ := a.authorities.List()
		currentBadge := a.ui.LabelBadge("未选择", false)
		certificateBadge := a.ui.LabelBadge("不可用", false)
		if current != "" {
			meta, e := a.repo.LoadAuthority(current)
			if e == nil {
				currentBadge = a.ui.LabelBadge(meta.Name, true)
				certificates, _ := a.certificates.List(current)
				certificateBadge = a.ui.LabelBadge(fmt.Sprintf("%d 张", len(certificates)), len(certificates) > 0)
			}
		}
		a.ui.MenuOptionStatusHint("1", "CA 管理", a.ui.LabelBadge(fmt.Sprintf("%d 个", len(authorities)), len(authorities) > 0), "创建、查看和选择签发机构")
		a.ui.MenuOptionStatusHint("2", "证书签发", currentBadge, "生成密钥签发或导入 CSR")
		a.ui.MenuOptionStatusHint("3", "证书管理", certificateBadge, "查询、续期和导出证书")
		a.ui.MenuOptionStatusHint("4", "吊销与 CRL", currentBadge, "永久吊销证书并管理 CRL")
		a.ui.MenuExit("0/q", "退出")
		a.ui.Printf("\n")
		choice, e := a.ui.Ask("请选择: ")
		if e != nil {
			if errors.Is(e, io.EOF) {
				return nil
			}
			return e
		}
		a.ui.Printf("\n")
		switch strings.ToLower(choice) {
		case "1":
			e = a.caMenu()
		case "2":
			e = a.issueMenu()
		case "3":
			e = a.certificateMenu()
		case "4":
			e = a.revocationMenu()
		case "0", "q", "exit":
			a.ui.Info("已退出")
			return nil
		default:
			a.ui.InvalidChoice()
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				return nil
			}
			a.ui.Error(e)
			a.ui.Pause()
		}
	}
}

func (a *App) caMenu() error {
	for {
		a.ui.Header("主菜单 / CA 管理")
		a.ui.MenuOptionHint("1", "创建根 CA", "自签名信任锚")
		a.ui.MenuOptionHint("2", "创建中间 CA", "由根 CA 签发")
		a.ui.MenuOptionHint("3", "CA 列表与详情", "查看证书和层级")
		a.ui.MenuOptionHint("4", "选择当前 CA", "用于后续签发和吊销")
		a.ui.MenuExit("0/q", "返回")
		a.ui.Printf("\n")
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
		case "0", "q", "exit":
			return nil
		default:
			a.ui.InvalidChoice()
		}
		if e != nil && !errors.Is(e, errCancelled) {
			a.ui.Error(e)
			a.ui.Pause()
		}
		e = nil
	}
}
func (a *App) createRoot() error {
	a.ui.Header("主菜单 / CA 管理 / 创建根 CA")
	a.ui.PrintInfoCard("根 CA 用途",
		ui.CardField{Label: "角色", Value: "自签名信任锚；用于签发一层中间 CA"},
		ui.CardField{Label: "默认算法", Value: "ECDSA P-384"},
		ui.CardField{Label: "默认有效期", Value: "3650 天（10 年）"},
		ui.CardField{Label: "私钥", Value: "强制使用口令加密，不会保存口令"},
	)
	a.ui.Printf("\n")
	name, e := a.askRequired("CA 名称（用于识别此信任锚，0 返回）: ", true)
	if e != nil {
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
		a.ui.PrintSuccessCard("根 CA 创建完成",
			ui.CardField{Label: "名称", Value: result.Name},
			ui.CardField{Label: "CA ID", Value: result.ID},
			ui.CardField{Label: "算法", Value: string(result.Algorithm)},
		)
		a.ui.Pause()
	}
	return e
}
func (a *App) createIntermediate() error {
	a.ui.Header("主菜单 / CA 管理 / 创建中间 CA")
	a.ui.PrintInfoCard("中间 CA 用途",
		ui.CardField{Label: "角色", Value: "日常签发服务器和客户端证书"},
		ui.CardField{Label: "层级", Value: "只能由根 CA 签发，不能继续签发下级 CA"},
		ui.CardField{Label: "默认有效期", Value: "1825 天（5 年），且不会超过父 CA"},
		ui.CardField{Label: "私钥", Value: "强制使用独立口令加密"},
	)
	a.ui.Printf("\n")
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
	name, e := a.askRequired("中间 CA 名称（用于识别签发机构，0 返回）: ", true)
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
		a.ui.PrintSuccessCard("中间 CA 创建完成",
			ui.CardField{Label: "名称", Value: result.Name},
			ui.CardField{Label: "CA ID", Value: result.ID},
			ui.CardField{Label: "父 CA", Value: result.ParentID},
		)
		a.ui.Pause()
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
		a.ui.Pause()
		return nil
	}
	for i, v := range items {
		kind := "根 CA"
		if !v.IsRoot() {
			kind = "中间 CA"
		}
		a.ui.MenuOptionStatusHint(strconv.Itoa(i+1), v.Name, a.ui.LabelBadge(kind, true), v.ID+" · 到期 "+v.NotAfter.Local().Format("2006-01-02"))
	}
	a.ui.MenuExit("0/q", "返回")
	a.ui.Printf("\n")
	n, e := a.askIndex("输入编号查看详情，0 返回: ", len(items))
	if e != nil {
		return e
	}
	v, c, e := a.authorities.Get(items[n-1].ID)
	if e != nil {
		return e
	}
	a.ui.Printf("\n")
	a.ui.PrintInfoCard("CA 详情",
		ui.CardField{Label: "ID", Value: v.ID},
		ui.CardField{Label: "名称", Value: v.Name},
		ui.CardField{Label: "父 CA", Value: emptyAs(v.ParentID, "无（自签名）")},
		ui.CardField{Label: "算法", Value: string(v.Algorithm)},
		ui.CardField{Label: "序列号", Value: c.SerialNumber.Text(16)},
		ui.CardField{Label: "有效期", Value: c.NotBefore.Local().Format(time.RFC3339) + " — " + c.NotAfter.Local().Format(time.RFC3339)},
		ui.CardField{Label: "路径长度", Value: strconv.Itoa(v.MaxPathLen)},
	)
	a.ui.Pause()
	return nil
}
func (a *App) selectAuthority() error {
	id, e := a.chooseAuthority(false)
	if e != nil || id == "" {
		return e
	}
	if e = a.authorities.Select(id); e == nil {
		a.ui.Info("当前 CA 已更新")
		a.ui.Pause()
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
		a.ui.MenuOptionHint(strconv.Itoa(i+1), v.Name, v.ID)
	}
	a.ui.MenuExit("0/q", "返回")
	a.ui.Printf("\n")
	n, e := a.askIndex("选择编号（决定后续操作使用哪个 CA，0 返回）: ", len(filtered))
	if e != nil {
		return "", e
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
		meta, _ := a.repo.LoadAuthority(ca)
		a.ui.PrintInfoCard("当前签发机构", ui.CardField{Label: "名称", Value: meta.Name}, ui.CardField{Label: "CA ID", Value: ca})
		a.ui.Printf("\n")
		a.ui.MenuOptionHint("1", "生成密钥并签发", "创建私钥和终端证书")
		a.ui.MenuOptionHint("2", "导入 PEM CSR 签发", "验证请求后仅签发证书")
		a.ui.MenuExit("0/q", "返回")
		a.ui.Printf("\n")
		v, e := a.ui.Ask("请选择: ")
		if e != nil {
			return e
		}
		switch strings.ToLower(v) {
		case "1":
			e = a.issueGenerated(ca)
		case "2":
			e = a.issueCSR(ca)
		case "0", "q", "exit":
			return nil
		default:
			a.ui.InvalidChoice()
		}
		if e != nil && !errors.Is(e, errCancelled) {
			a.ui.Error(e)
			a.ui.Pause()
		}
		e = nil
	}
}
func (a *App) issueGenerated(ca string) error {
	a.ui.Header("主菜单 / 证书签发 / 生成密钥")
	a.ui.PrintInfoCard("签发说明",
		ui.CardField{Label: "服务器证书", Value: "用于 HTTPS/TLS 服务，必须提供 DNS 或 IP SAN"},
		ui.CardField{Label: "客户端证书", Value: "用于用户、设备或服务的双向 TLS 身份认证"},
		ui.CardField{Label: "私钥", Value: "由 CAForge 新建并保存，可选择口令加密"},
	)
	a.ui.Printf("\n")
	profile, e := a.chooseProfile()
	if e != nil {
		return e
	}
	cn, e := a.askRequired("通用名称 CN（证书主要显示名称，0 返回）: ", true)
	if e != nil {
		return e
	}
	var dns, ips []string
	if profile == domain.Server {
		for {
			d, err := a.ui.Ask("DNS SAN（客户端访问使用的域名，逗号分隔，可空）: ")
			if err != nil {
				return err
			}
			if ui.IsBack(d) {
				return errCancelled
			}
			i, err := a.ui.Ask("IP SAN（客户端访问使用的 IP，逗号分隔，可空）: ")
			if err != nil {
				return err
			}
			if ui.IsBack(i) {
				return errCancelled
			}
			dns, ips = csv(d), csv(i)
			if err = certificate.ValidateSANs(dns, ips); err != nil {
				a.ui.Warning(err.Error() + "，请重新输入 SAN")
				continue
			}
			break
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
	encrypt, e := a.chooseKeyEncryption()
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
		a.ui.PrintWarningCard("明文私钥风险",
			ui.CardField{Label: "保护状态", Value: a.ui.LabelBadge("未加密", false)},
			ui.CardField{Label: "风险", Value: "文件泄露后无法通过口令阻止使用"},
		)
		ok, e := a.ui.Confirm("确认生成明文私钥？")
		if e != nil {
			return e
		}
		if !ok {
			return errCancelled
		}
	}
	caPW, e := a.ui.Password("CA 私钥口令: ")
	if e != nil {
		return e
	}
	result, e := a.certificates.Issue(domain.IssueRequest{CAID: ca, CommonName: cn, Profile: profile, Algorithm: alg, DNSNames: dns, IPAddresses: ips, Days: days, EncryptKey: encrypt, KeyPassword: keyPW}, caPW)
	if e == nil {
		a.ui.PrintSuccessCard("证书签发完成",
			ui.CardField{Label: "通用名称", Value: result.CommonName},
			ui.CardField{Label: "序列号", Value: result.Serial},
			ui.CardField{Label: "模板", Value: string(result.Profile)},
			ui.CardField{Label: "有效期至", Value: result.NotAfter.Local().Format(time.RFC3339)},
		)
		a.ui.Pause()
	}
	return e
}
func (a *App) issueCSR(ca string) error {
	a.ui.Header("主菜单 / 证书签发 / CSR 签发")
	a.ui.PrintInfoCard("CSR 签发说明",
		ui.CardField{Label: "签名", Value: "验证 CSR 自身签名和公钥强度"},
		ui.CardField{Label: "扩展", Value: "只采用经过校验的 SAN，不复制未知扩展或 CA 权限"},
		ui.CardField{Label: "私钥", Value: "仍由 CSR 申请者保管，CAForge 不保存"},
	)
	a.ui.Printf("\n")
	_, data, e := a.askReadableFile("CSR PEM 文件路径（0 返回）: ")
	if e != nil {
		return e
	}
	profile, e := a.chooseProfile()
	if e != nil {
		return e
	}
	name, e := a.ui.Ask("覆盖通用名称 CN（留空使用 CSR 内的名称，0 返回）: ")
	if e != nil {
		return e
	}
	if ui.IsBack(name) {
		return errCancelled
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
		a.ui.PrintSuccessCard("CSR 签发完成",
			ui.CardField{Label: "通用名称", Value: result.CommonName},
			ui.CardField{Label: "序列号", Value: result.Serial},
			ui.CardField{Label: "私钥", Value: a.ui.LabelBadge("不由 CAForge 保存", false)},
		)
		a.ui.Pause()
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
			a.ui.PrintField("筛选", filter+"（输入 f 可修改）")
			a.ui.Printf("\n")
		}
		if len(items) == 0 && filter == "" {
			a.ui.Warning("当前 CA 尚未签发证书")
			a.ui.Pause()
			return nil
		}
		if len(items) == 0 {
			a.ui.Warning("没有匹配的证书")
		}
		for i, c := range items {
			_, _, status, _ := a.certificates.Get(ca, c.Serial)
			a.ui.MenuOptionStatusHint(strconv.Itoa(i+1), c.CommonName, a.ui.Badge(status), c.Serial+" · "+string(c.Profile))
		}
		a.ui.MenuOptionHint("f", "筛选证书", "按序列号、通用名称或模板查找")
		a.ui.MenuExit("0/q", "返回")
		a.ui.Printf("\n")
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
			a.ui.InvalidChoice()
			continue
		}
		if e = a.certificateActions(ca, items[n-1].Serial); e != nil && !errors.Is(e, errCancelled) {
			a.ui.Error(e)
			a.ui.Pause()
		}
		e = nil
	}
}
func (a *App) certificateActions(ca, serial string) error {
	for {
		meta, cert, status, e := a.certificates.Get(ca, serial)
		if e != nil {
			return e
		}
		a.ui.Header("主菜单 / 证书管理 / " + serial)
		a.ui.PrintInfoCard("证书详情",
			ui.CardField{Label: "状态", Value: a.ui.Badge(status)},
			ui.CardField{Label: "通用名称", Value: meta.CommonName},
			ui.CardField{Label: "模板", Value: string(meta.Profile)},
			ui.CardField{Label: "算法", Value: string(meta.Algorithm)},
			ui.CardField{Label: "有效期", Value: cert.NotBefore.Local().Format(time.RFC3339) + " — " + cert.NotAfter.Local().Format(time.RFC3339)},
			ui.CardField{Label: "DNS SAN", Value: emptyAs(strings.Join(meta.DNSNames, ", "), "无")},
			ui.CardField{Label: "IP SAN", Value: emptyAs(strings.Join(meta.IPAddresses, ", "), "无")},
			ui.CardField{Label: "续期来源", Value: emptyAs(meta.RenewedFrom, "无")},
		)
		a.ui.Printf("\n")
		a.ui.MenuOptionHint("1", "查看证书链", "PEM 格式")
		a.ui.MenuOptionHint("2", "续期", "生成新密钥，保留旧证书")
		a.ui.MenuOptionHint("3", "导出 PEM", "证书、私钥和完整链")
		a.ui.MenuOptionHint("4", "导出 PKCS#12", "带口令的完整证书链")
		a.ui.MenuExit("0/q", "返回")
		a.ui.Printf("\n")
		v, e := a.ui.Ask("请选择: ")
		if e != nil {
			return e
		}
		switch strings.ToLower(v) {
		case "1":
			chain, e := a.certificates.CertificateChain(ca, serial)
			if e == nil {
				a.ui.MenuSection("PEM 证书链")
				a.ui.Printf("%s\n", chain)
				a.ui.Pause()
			}
		case "2":
			e = a.renew(ca, serial)
		case "3":
			e = a.exportCertificate(ca, serial, domain.ExportPEM)
		case "4":
			e = a.exportCertificate(ca, serial, domain.ExportPKCS12)
		case "0", "q", "exit":
			return nil
		default:
			a.ui.InvalidChoice()
		}
		if e != nil && !errors.Is(e, errCancelled) {
			a.ui.Error(e)
			a.ui.Pause()
		}
		e = nil
	}
}
func (a *App) renew(ca, serial string) error {
	days, e := a.days("新证书有效天数 [397]: ", 397)
	if e != nil {
		return e
	}
	encrypt, e := a.chooseKeyEncryption()
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
		a.ui.PrintWarningCard("明文私钥风险", ui.CardField{Label: "续期私钥", Value: a.ui.LabelBadge("未加密", false)}, ui.CardField{Label: "风险", Value: "文件泄露后无法通过口令阻止使用"})
		ok, e := a.ui.Confirm("确认？")
		if e != nil {
			return e
		}
		if !ok {
			return errCancelled
		}
	}
	caPW, e := a.ui.Password("CA 私钥口令: ")
	if e != nil {
		return e
	}
	result, e := a.certificates.Renew(ca, serial, days, caPW, keyPW, encrypt)
	if e == nil {
		a.ui.PrintSuccessCard("证书续期完成",
			ui.CardField{Label: "旧序列号", Value: serial, Detail: "旧证书保留且未自动吊销"},
			ui.CardField{Label: "新序列号", Value: result.Serial},
			ui.CardField{Label: "有效期至", Value: result.NotAfter.Local().Format(time.RFC3339)},
		)
		a.ui.Pause()
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
			return errCancelled
		}
	}
	if e = os.WriteFile(filepath.Clean(path), data, 0600); e == nil {
		e = os.Chmod(filepath.Clean(path), 0600)
	}
	if e == nil {
		a.ui.PrintSuccessCard("证书导出完成", ui.CardField{Label: "格式", Value: string(format)}, ui.CardField{Label: "文件", Value: path})
		a.ui.Pause()
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
		a.ui.MenuOptionHint("1", "吊销证书", "不可撤销并立即更新 CRL")
		a.ui.MenuOptionHint("2", "查看 CRL", "编号、更新时间和吊销条目")
		a.ui.MenuOptionHint("3", "重新生成 CRL", "默认 nextUpdate 为 7 天")
		a.ui.MenuExit("0/q", "返回")
		a.ui.Printf("\n")
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
				a.ui.PrintInfoCard("CRL 详情",
					ui.CardField{Label: "编号", Value: crl.Number.String()},
					ui.CardField{Label: "thisUpdate", Value: crl.ThisUpdate.Local().Format(time.RFC3339)},
					ui.CardField{Label: "nextUpdate", Value: crl.NextUpdate.Local().Format(time.RFC3339)},
					ui.CardField{Label: "吊销条目", Value: fmt.Sprintf("%d 条", len(crl.RevokedCertificateEntries))},
				)
				a.ui.Pause()
			}
		case "3":
			pw, er := a.ui.Password("CA 私钥口令: ")
			e = er
			if er == nil {
				e = a.revocations.Generate(ca, pw)
				if e == nil {
					a.ui.PrintSuccessCard("CRL 已重新生成", ui.CardField{Label: "CA ID", Value: ca}, ui.CardField{Label: "有效期", Value: "7 天"})
					a.ui.Pause()
				}
			}
		case "0", "q", "exit":
			return nil
		default:
			a.ui.InvalidChoice()
		}
		if e != nil && !errors.Is(e, errCancelled) {
			a.ui.Error(e)
			a.ui.Pause()
		}
		e = nil
	}
}
func (a *App) revoke(ca string) error {
	items, e := a.certificates.List(ca)
	if e != nil {
		return e
	}
	if len(items) == 0 {
		a.ui.Warning("当前 CA 没有可吊销的签发记录")
		a.ui.Pause()
		return nil
	}
	for i, c := range items {
		_, _, status, _ := a.certificates.Get(ca, c.Serial)
		a.ui.MenuOptionStatusHint(strconv.Itoa(i+1), c.CommonName, a.ui.Badge(status), c.Serial)
	}
	a.ui.MenuExit("0/q", "返回")
	a.ui.Printf("\n")
	n, e := a.askIndex("选择要永久吊销的证书编号（0 返回）: ", len(items))
	if e != nil {
		return e
	}
	serial := items[n-1].Serial
	reasons := revocation.Reasons()
	for i, r := range reasons {
		a.ui.MenuOptionHint(strconv.Itoa(i+1), r.Label, revocationReasonHint(r.Value))
	}
	a.ui.MenuExit("0/q", "返回")
	a.ui.Printf("\n")
	ri, e := a.askIndex("选择最符合实际情况的吊销原因（0 返回）: ", len(reasons))
	if e != nil {
		return e
	}
	a.ui.Printf("\n")
	a.ui.PrintDangerCard("确认永久吊销",
		ui.CardField{Label: "证书", Value: items[n-1].CommonName},
		ui.CardField{Label: "序列号", Value: serial},
		ui.CardField{Label: "吊销原因", Value: reasons[ri-1].Label},
		ui.CardField{Label: "影响", Value: "此操作不可撤销；成功后立即更新 CRL"},
	)
	for {
		confirm, err := a.ui.Ask("请输入“吊销 " + serial + "”确认，或输入 0 返回: ")
		if err != nil {
			return err
		}
		if ui.IsBack(confirm) {
			return errCancelled
		}
		if confirm != "吊销 "+serial {
			a.ui.Warning("确认文字不匹配，证书尚未吊销，请重新输入")
			continue
		}
		break
	}
	pw, e := a.ui.Password("CA 私钥口令: ")
	if e != nil {
		return e
	}
	if e = a.revocations.Revoke(ca, serial, reasons[ri-1].Value, pw); e == nil {
		a.ui.PrintDangerCard("证书已吊销",
			ui.CardField{Label: "序列号", Value: serial},
			ui.CardField{Label: "吊销原因", Value: reasons[ri-1].Label},
			ui.CardField{Label: "CRL", Value: "PEM 和 DER 已更新"},
		)
		a.ui.Pause()
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
	for {
		a.ui.MenuSection("选择证书模板")
		a.ui.MenuOptionHint("1", "服务器证书", "ServerAuth；用于 HTTPS/TLS 服务，必须包含 DNS/IP SAN")
		a.ui.MenuOptionHint("2", "客户端证书", "ClientAuth；用于用户、设备或服务身份认证")
		a.ui.MenuExit("0/q", "返回")
		a.ui.Printf("\n")
		v, e := a.ui.Ask("请选择证书用途: ")
		if e != nil {
			return "", e
		}
		switch strings.ToLower(v) {
		case "1":
			return domain.Server, nil
		case "2":
			return domain.Client, nil
		case "0", "q", "exit":
			return "", errCancelled
		default:
			a.ui.InvalidChoice()
		}
	}
}
func (a *App) chooseAlgorithm(ca bool) (domain.Algorithm, error) {
	if ca {
		for {
			a.ui.MenuSection("选择 CA 密钥算法")
			a.ui.MenuOptionHint("1", "ECDSA P-384", "默认推荐；密钥小、签名快、安全强度高")
			a.ui.MenuOptionHint("2", "RSA-3072", "兼容只支持 RSA 的旧系统")
			a.ui.MenuOptionHint("3", "RSA-4096", "更大 RSA 密钥；生成和签名更慢")
			a.ui.MenuExit("0/q", "返回")
			a.ui.Printf("\n")
			v, e := a.ui.Ask("请选择密钥算法 [1]: ")
			if e != nil {
				return "", e
			}
			switch strings.ToLower(v) {
			case "", "1":
				return domain.ECDSAP384, nil
			case "2":
				return domain.RSA3072, nil
			case "3":
				return domain.RSA4096, nil
			case "0", "q", "exit":
				return "", errCancelled
			default:
				a.ui.InvalidChoice()
			}
		}
	}
	for {
		a.ui.MenuSection("选择终端密钥算法")
		a.ui.MenuOptionHint("1", "ECDSA P-256", "默认推荐；适合现代 TLS，密钥和证书更小")
		a.ui.MenuOptionHint("2", "RSA-3072", "用于必须兼容 RSA 的客户端或服务")
		a.ui.MenuExit("0/q", "返回")
		a.ui.Printf("\n")
		v, e := a.ui.Ask("请选择密钥算法 [1]: ")
		if e != nil {
			return "", e
		}
		switch strings.ToLower(v) {
		case "", "1":
			return domain.ECDSAP256, nil
		case "2":
			return domain.RSA3072, nil
		case "0", "q", "exit":
			return "", errCancelled
		default:
			a.ui.InvalidChoice()
		}
	}
}
func (a *App) days(prompt string, def int) (int, error) {
	for {
		v, e := a.ui.Ask(prompt)
		if e != nil {
			return 0, e
		}
		if ui.IsBack(v) {
			return 0, errCancelled
		}
		days, err := store.ParsePositiveDays(v, def)
		if err != nil {
			a.ui.Warning(err.Error() + "，例如输入 397；输入 0 可返回")
			continue
		}
		return days, nil
	}
}
func (a *App) confirmedPassword(prompt string) ([]byte, error) {
	for {
		first, e := a.ui.Password(prompt)
		if e != nil {
			return nil, e
		}
		if len(first) == 0 {
			a.ui.Warning("口令不能为空，请重新输入")
			continue
		}
		second, e := a.ui.Password("再次输入口令: ")
		if e != nil {
			return nil, e
		}
		if string(first) != string(second) {
			a.ui.Warning("两次口令不一致，请重新设置")
			continue
		}
		return first, nil
	}
}

func (a *App) askRequired(prompt string, allowBack bool) (string, error) {
	for {
		value, err := a.ui.Ask(prompt)
		if err != nil {
			return "", err
		}
		if allowBack && ui.IsBack(value) {
			return "", errCancelled
		}
		if strings.TrimSpace(value) == "" {
			a.ui.Warning("此项不能为空，请重新输入")
			continue
		}
		return strings.TrimSpace(value), nil
	}
}

func (a *App) askIndex(prompt string, count int) (int, error) {
	for {
		value, err := a.ui.Ask(prompt)
		if err != nil {
			return 0, err
		}
		if ui.IsBack(value) {
			return 0, errCancelled
		}
		index, err := strconv.Atoi(value)
		if err != nil || index < 1 || index > count {
			a.ui.Warning(fmt.Sprintf("请输入 1 到 %d 之间的编号，或输入 0/q 返回", count))
			continue
		}
		return index, nil
	}
}

func (a *App) askReadableFile(prompt string) (string, []byte, error) {
	for {
		path, err := a.ui.Ask(prompt)
		if err != nil {
			return "", nil, err
		}
		if ui.IsBack(path) {
			return "", nil, errCancelled
		}
		if strings.TrimSpace(path) == "" {
			a.ui.Warning("文件路径不能为空，请重新输入")
			continue
		}
		clean := filepath.Clean(path)
		data, err := os.ReadFile(clean)
		if err != nil {
			a.ui.Warning("无法读取文件：" + err.Error() + "；请检查路径后重新输入")
			continue
		}
		return clean, data, nil
	}
}

func (a *App) chooseKeyEncryption() (bool, error) {
	for {
		a.ui.MenuSection("选择私钥保护方式")
		a.ui.MenuOptionHint("1", "口令加密", "推荐；私钥文件泄露后仍需口令才能使用")
		a.ui.MenuOptionHint("2", "明文保存", "仅用于受严格权限保护的兼容场景，泄露后可直接使用")
		a.ui.MenuExit("0/q", "返回")
		a.ui.Printf("\n")
		value, err := a.ui.Ask("请选择保护方式 [1]: ")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(value) {
		case "", "1":
			return true, nil
		case "2":
			return false, nil
		case "0", "q", "exit":
			return false, errCancelled
		default:
			a.ui.InvalidChoice()
		}
	}
}

func revocationReasonHint(reason domain.RevocationReason) string {
	switch reason {
	case domain.Unspecified:
		return "无法归入其他原因时使用"
	case domain.KeyCompromise:
		return "证书对应私钥已泄露或疑似泄露"
	case domain.CACompromise:
		return "签发机构私钥已泄露；通常用于 CA 证书"
	case domain.AffiliationChanged:
		return "持有者的组织、域名或从属关系已变化"
	case domain.Superseded:
		return "已有新证书替代当前证书"
	case domain.CessationOfOperation:
		return "服务、设备或实体已停止运营"
	case domain.CertificateHold:
		return "临时暂停使用；CAForge 首版仍不可撤销"
	case domain.PrivilegeWithdrawn:
		return "证书持有者的授权或权限已撤回"
	case domain.AACompromise:
		return "属性授权机构已泄露"
	default:
		return "RFC 5280 吊销原因"
	}
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
