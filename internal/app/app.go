package app

import (
	"crypto/x509"
	"encoding/pem"
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
	FilePaths(string, string) (certificate.FilePaths, error)
	DeploymentMaterials(string, string) (certificate.DeploymentMaterials, error)
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
		paths, e := a.certificates.FilePaths(ca, serial)
		if e != nil {
			return e
		}
		a.ui.Header("主菜单 / 证书管理 / " + serial)
		fields := []ui.CardField{
			ui.CardField{Label: "状态", Value: a.ui.Badge(status)},
			ui.CardField{Label: "通用名称", Value: meta.CommonName},
			ui.CardField{Label: "模板", Value: string(meta.Profile)},
			ui.CardField{Label: "算法", Value: string(meta.Algorithm)},
			ui.CardField{Label: "有效期", Value: cert.NotBefore.Local().Format(time.RFC3339) + " — " + cert.NotAfter.Local().Format(time.RFC3339)},
			ui.CardField{Label: "DNS SAN", Value: emptyAs(strings.Join(meta.DNSNames, ", "), "无")},
			ui.CardField{Label: "IP SAN", Value: emptyAs(strings.Join(meta.IPAddresses, ", "), "无")},
			ui.CardField{Label: "续期来源", Value: emptyAs(meta.RenewedFrom, "无")},
			ui.CardField{Label: "记录目录", Value: paths.Directory},
			ui.CardField{Label: "证书文件", Value: paths.Certificate},
			ui.CardField{Label: "完整证书链", Value: paths.Chain},
		}
		if paths.PrivateKey != "" {
			fields = append(fields, ui.CardField{Label: "私钥文件", Value: paths.PrivateKey, Detail: "敏感文件，权限为 0600"})
		} else {
			fields = append(fields, ui.CardField{Label: "私钥文件", Value: "无（CAForge 未保存此记录的私钥）"})
		}
		if paths.RequestCSR != "" {
			fields = append(fields, ui.CardField{Label: "原始 CSR", Value: paths.RequestCSR})
		}
		a.ui.PrintInfoCard("证书详情", fields...)
		a.ui.Printf("\n")
		a.ui.MenuOptionHint("1", "查看证书链", "按终端证书 → 中间 CA → 根 CA 展示，不含私钥")
		a.ui.MenuOptionHint("2", "续期", "生成新密钥，保留旧证书")
		a.ui.MenuOptionHint("3", "导出 PEM", "证书、私钥和完整链")
		a.ui.MenuOptionHint("4", "导出 PKCS#12", "带口令的完整证书链")
		a.ui.MenuOptionHint("5", "查看并复制部署文件", "仅显示私钥、部署用完整链和根 CA")
		switch meta.Profile {
		case domain.Server:
			a.ui.MenuOptionHint("6", "查看服务器部署说明", "服务器所需文件、fullchain 顺序和客户端信任关系")
		case domain.Client:
			a.ui.MenuOptionHint("6", "查看客户端使用说明", "mTLS 客户端导入和服务器信任配置")
		default:
			a.ui.MenuOptionHint("6", "查看中间 CA 使用说明", "签发链、根 CA 信任关系和私钥保护")
		}
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
				e = a.showCertificateChain(chain)
			}
			if e == nil {
				a.ui.Pause()
			}
		case "2":
			e = a.renew(ca, serial)
		case "3":
			e = a.exportCertificate(ca, serial, domain.ExportPEM)
		case "4":
			e = a.exportCertificate(ca, serial, domain.ExportPKCS12)
		case "5":
			e = a.showCopyableCertificateFiles(ca, serial, meta)
			if e == nil {
				a.ui.Pause()
			}
		case "6":
			a.showCertificateUsage(meta)
			a.ui.Pause()
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

func (a *App) showCopyableCertificateFiles(ca, serial string, meta domain.Certificate) error {
	materials, err := a.certificates.DeploymentMaterials(ca, serial)
	if err != nil {
		return err
	}

	a.ui.Printf("\n")
	warningFields := []ui.CardField{
		{Label: "终端记录", Value: "以下 PEM 内容会保留在终端滚动记录中"},
		{Label: "操作环境", Value: "仅在自己的受控终端查看；不要粘贴到聊天、工单或公开日志"},
	}
	if len(materials.PrivateKeyPEM) > 0 {
		warningFields = append(warningFields, ui.CardField{Label: "敏感内容", Value: a.ui.LabelBadge("包含私钥", false), Detail: "任何取得私钥的人都可能冒充该服务器或客户端"})
	} else {
		warningFields = append(warningFields, ui.CardField{Label: "私钥", Value: "此记录不保存私钥，只显示公开证书"})
	}
	a.ui.PrintDangerCard("显示可复制部署文件前请确认", warningFields...)
	ok, err := a.ui.Confirm("确认在终端显示这些内容？")
	if err != nil {
		return err
	}
	if !ok {
		return errCancelled
	}

	keyName := "certificate.key.pem"
	fullChainName, fullChainPurpose := "certificate.fullchain.pem", "当前证书 + 中间 CA，不含根 CA"
	switch meta.Profile {
	case domain.Server:
		keyName = "server.key.pem"
		fullChainName = "server.fullchain.pem"
		fullChainPurpose = "服务器证书 + 中间 CA，不含根 CA；用于 Nginx ssl_certificate 等完整链配置"
	case domain.Client:
		keyName = "client.key.pem"
		fullChainName = "client.fullchain.pem"
		fullChainPurpose = "客户端证书 + 中间 CA，不含根 CA；供要求发送客户端完整链的程序使用"
	case domain.Intermediate:
		keyName = "intermediate-ca.key.pem"
		fullChainName = "intermediate-ca.chain.pem"
		fullChainPurpose = "中间 CA 链，不含根 CA；供需要中间证书链的程序使用"
	}

	if len(materials.PrivateKeyPEM) > 0 && meta.Profile != domain.Intermediate {
		keyState := "明文私钥"
		if materials.PrivateKeyEncrypted {
			keyState = "口令加密私钥"
		}
		a.printCopyablePEM("[1] 私钥（敏感）", keyName, keyState+"；只部署到对应服务器、客户端或服务，文件权限应为 0600", materials.PrivateKeyPEM)
	} else {
		detail := "该证书由外部 CSR 签发；CAForge 没有私钥。请从生成 CSR 的服务器或客户端取得原始私钥，证书必须与它配套使用。"
		if meta.Profile == domain.Intermediate {
			detail = "CA 私钥不会在证书管理界面显示。请只在 CAForge 的受控 CA 数据目录中使用和保护它。"
		}
		a.ui.Printf("\n")
		a.ui.PrintWarningCard("[1] 私钥未显示",
			ui.CardField{Label: "建议文件名", Value: keyName},
			ui.CardField{Label: "说明", Value: detail},
		)
	}

	a.printCopyablePEM("[2] 部署用完整链", fullChainName, fullChainPurpose, materials.FullChainPEM)

	rootPurpose := "客户端安装证书 CA：复制到访问服务器的客户端，并导入系统或应用信任库"
	if meta.Profile == domain.Client {
		rootPurpose = "mTLS 服务器信任的根 CA：服务器用它验证该客户端证书，不要把客户端私钥交给服务器"
	} else if meta.Profile == domain.Intermediate {
		rootPurpose = "根 CA 信任锚：导入信任库后，可验证该中间 CA 签发的终端证书"
	}
	a.printCopyablePEM("[3] 根 CA 证书（信任锚）", "root-ca.pem", rootPurpose, materials.RootCAPEM)

	a.ui.Printf("\n")
	a.ui.PrintWarningCard("复制后的文件权限",
		ui.CardField{Label: "私钥", Value: "0600，仅所属服务账户可读"},
		ui.CardField{Label: "公开证书", Value: "0644；可公开分发，但应防止被意外替换"},
		ui.CardField{Label: "注意", Value: "复制 PEM 时必须保留 BEGIN/END 行及其间全部内容"},
	)
	return nil
}

func (a *App) printCopyablePEM(title, filename, purpose string, contents []byte) {
	a.ui.Printf("\n")
	a.ui.MenuSection(title)
	a.ui.PrintInfoCard("对应文件",
		ui.CardField{Label: "建议文件名", Value: filename},
		ui.CardField{Label: "用途", Value: purpose},
	)
	a.ui.Printf("\n%s", contents)
}

func (a *App) showCertificateUsage(certificate domain.Certificate) {
	switch certificate.Profile {
	case domain.Server:
		privateKey := "服务器证书对应的私钥；必须单独保存并限制为 0600"
		if !certificate.HasKey {
			privateKey = "CSR 签发记录不保存私钥；请使用生成 CSR 时保留的原始私钥"
		}
		a.ui.Printf("\n")
		a.ui.PrintInfoCard("服务器部署所需文件",
			ui.CardField{Label: "服务器证书", Value: certificate.CommonName + "（序列号 " + certificate.Serial + "）", Detail: "证明服务器身份"},
			ui.CardField{Label: "服务器私钥", Value: privateKey},
			ui.CardField{Label: "中间 CA", Value: "随服务器证书发送，帮助客户端构建信任链"},
		)
		a.ui.Printf("\n")
		a.ui.PrintInfoCard("推荐文件结构",
			ui.CardField{Label: "server.fullchain.pem", Value: "服务器证书 → 中间 CA 证书", Detail: "根 CA 通常不放入服务器 fullchain"},
			ui.CardField{Label: "server.key.pem", Value: "仅包含服务器私钥", Detail: "不得公开、提交到代码仓库或发送给客户端"},
			ui.CardField{Label: "客户端信任库", Value: "安装根 CA 证书", Detail: "根 CA 是信任锚，不是服务器身份文件"},
		)
		a.ui.Printf("\n")
		a.ui.PrintWarningCard("部署注意",
			ui.CardField{Label: "PEM 导出", Value: "组合导出包含证书、私钥和完整链，不应直接作为 Nginx ssl_certificate"},
			ui.CardField{Label: "主机名验证", Value: "客户端访问地址必须匹配证书的 DNS 或 IP SAN"},
		)
		return
	case domain.Client:
		privateKey := "随 CAForge 生成的客户端私钥一起使用"
		if !certificate.HasKey {
			privateKey = "使用生成 CSR 时保留的原始客户端私钥"
		}
		a.ui.Printf("\n")
		a.ui.PrintInfoCard("客户端证书使用方式",
			ui.CardField{Label: "客户端证书", Value: certificate.CommonName + "（序列号 " + certificate.Serial + "）"},
			ui.CardField{Label: "客户端私钥", Value: privateKey, Detail: "只保存在对应用户、设备或服务上"},
			ui.CardField{Label: "推荐导入", Value: "使用带强口令的 PKCS#12 导入浏览器、系统或应用"},
			ui.CardField{Label: "服务器配置", Value: "启用 mTLS，并信任签发此证书的根 CA"},
		)
	case domain.Intermediate:
		a.ui.Printf("\n")
		a.ui.PrintInfoCard("中间 CA 使用方式",
			ui.CardField{Label: "中间 CA 证书", Value: certificate.CommonName + "（序列号 " + certificate.Serial + "）", Detail: "随终端证书提供，帮助验证方构建信任链"},
			ui.CardField{Label: "根 CA 证书", Value: "安装到验证方的信任库，作为最终信任锚"},
			ui.CardField{Label: "CA 私钥", Value: a.ui.LabelBadge("不得复制到业务服务器", false), Detail: "只应保存在 CAForge 的受控 CA 环境中，用于签发和吊销"},
		)
	}
}

func (a *App) showCertificateChain(chain []byte) error {
	type chainItem struct {
		certificate *x509.Certificate
		pem         []byte
	}
	var items []chainItem
	rest := chain
	for len(strings.TrimSpace(string(rest))) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return errors.New("证书链包含无法解析的 PEM 数据")
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("证书链包含非证书 PEM 块 %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("解析证书链失败: %w", err)
		}
		items = append(items, chainItem{certificate: certificate, pem: pem.EncodeToMemory(block)})
	}
	if len(items) == 0 {
		return errors.New("证书链为空")
	}

	a.ui.Printf("\n")
	a.ui.PrintInfoCard("证书链说明",
		ui.CardField{Label: "顺序", Value: "终端证书 → 中间 CA → 根 CA"},
		ui.CardField{Label: "验证", Value: "每一项由下一项签发，最后由受信任的根 CA 建立信任"},
		ui.CardField{Label: "安全", Value: a.ui.LabelBadge("仅公开证书，不含私钥", true)},
	)

	for index, item := range items {
		role, purpose := certificateRole(item.certificate, index, len(items))
		a.ui.Printf("\n")
		a.ui.MenuSection(fmt.Sprintf("[%d/%d] %s", index+1, len(items), role))
		a.ui.PrintInfoCard(item.certificate.Subject.CommonName,
			ui.CardField{Label: "角色", Value: role},
			ui.CardField{Label: "用途", Value: purpose},
			ui.CardField{Label: "主题", Value: item.certificate.Subject.String()},
			ui.CardField{Label: "签发者", Value: item.certificate.Issuer.String()},
			ui.CardField{Label: "序列号", Value: strings.ToUpper(item.certificate.SerialNumber.Text(16))},
			ui.CardField{Label: "有效期", Value: item.certificate.NotBefore.Local().Format(time.RFC3339) + " — " + item.certificate.NotAfter.Local().Format(time.RFC3339)},
		)
		a.ui.Printf("\n%s", item.pem)
	}
	return nil
}

func certificateRole(certificate *x509.Certificate, index, total int) (string, string) {
	if !certificate.IsCA {
		return "终端证书", "提供给服务器或客户端使用，由上级 CA 验证身份"
	}
	if index == total-1 && certificate.Subject.String() == certificate.Issuer.String() && certificate.CheckSignatureFrom(certificate) == nil {
		return "根 CA 证书（信任锚）", "安装到客户端或系统信任库，用于建立整条证书链的最终信任"
	}
	return "中间 CA 证书", "隔离根 CA 与日常签发操作，用于验证下一级证书"
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
	path, e = filepath.Abs(filepath.Clean(path))
	if e != nil {
		return fmt.Errorf("无法解析输出路径: %w", e)
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
	if e = os.WriteFile(path, data, 0600); e == nil {
		e = os.Chmod(path, 0600)
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
