package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	orange = "\x1b[38;5;208m"
	blue   = "\x1b[34m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	red    = "\x1b[31m"
	gray   = "\x1b[90m"
)

type PasswordReader func(prompt string) ([]byte, error)

type CardField struct {
	Label  string
	Value  string
	Detail string
}

type Terminal struct {
	in          *bufio.Reader
	out         io.Writer
	errOut      io.Writer
	color       bool
	interactive bool
	password    PasswordReader
}

func New(in io.Reader, out io.Writer, color bool, password PasswordReader) *Terminal {
	t := &Terminal{in: bufio.NewReader(in), out: out, errOut: out, color: color, interactive: color, password: password}
	if t.password == nil {
		t.password = t.linePassword
	}
	return t
}

func NewConsole() *Terminal {
	interactive := term.IsTerminal(int(os.Stdout.Fd())) && !strings.EqualFold(os.Getenv("TERM"), "dumb")
	_, noColor := os.LookupEnv("NO_COLOR")
	color := interactive && !noColor
	if forced := os.Getenv("CLICOLOR_FORCE"); !noColor && forced != "" && forced != "0" && !strings.EqualFold(os.Getenv("TERM"), "dumb") {
		color = true
	}
	t := New(os.Stdin, os.Stdout, color, nil)
	t.errOut = os.Stderr
	t.interactive = interactive
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.password = func(prompt string) ([]byte, error) {
			fmt.Fprint(os.Stdout, t.prompt(prompt))
			b, e := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stdout)
			return b, e
		}
	}
	return t
}

func (t *Terminal) linePassword(prompt string) ([]byte, error) {
	v, e := t.Ask(prompt)
	return []byte(v), e
}

func (t *Terminal) paint(style, text string) string {
	if !t.color {
		return text
	}
	return style + text + reset
}

func (t *Terminal) Clear() {
	if t.interactive {
		fmt.Fprint(t.out, "\x1b[2J\x1b[H\x1b[3J")
	}
}

func (t *Terminal) Header(path string) {
	t.Clear()
	parts := []string{"CAForge"}
	for _, part := range strings.Split(path, "/") {
		if part = strings.TrimSpace(part); part != "" && part != "主菜单" {
			parts = append(parts, part)
		}
	}
	title := strings.Join(parts, "  ›  ")
	fmt.Fprintln(t.out, t.paint(orange, "╭─")+" "+t.paint(bold+orange, title))
	fmt.Fprintln(t.out, t.paint(orange, "╰"+strings.Repeat("─", 46)))
	fmt.Fprintln(t.out)
}

func (t *Terminal) HomeHeader(buildVersion string) {
	buildVersion = strings.TrimSpace(buildVersion)
	if buildVersion == "" {
		buildVersion = "dev"
	}
	t.Clear()
	fmt.Fprintln(t.out, t.paint(orange, "╭─")+" "+t.paint(bold+orange, "CAForge"))
	fmt.Fprintln(t.out, t.paint(orange, "│")+" "+t.paint(orange, "本地 CA 管理工具")+"  "+t.LabelBadge("版本 "+buildVersion, true))
	fmt.Fprintln(t.out, t.paint(orange, "╰"+strings.Repeat("─", 46)))
	fmt.Fprintln(t.out)
}

func (t *Terminal) MenuOption(key, label string) {
	fmt.Fprintf(t.out, "  %s %s\n", t.menuKey(key, bold+blue), label)
}

func (t *Terminal) MenuOptionHint(key, label, hint string) {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		t.MenuOption(key, label)
		return
	}
	fmt.Fprintf(t.out, "  %s %s%s\n", t.menuKey(key, bold+blue), t.padDisplay(label, 22), t.paint(gray, "-- "+hint))
}

func (t *Terminal) MenuOptionStatus(key, label, status string) {
	status = strings.TrimSpace(status)
	if status == "" {
		t.MenuOption(key, label)
		return
	}
	fmt.Fprintf(t.out, "  %s %s%s\n", t.menuKey(key, bold+blue), t.padDisplay(label, 18), status)
}

func (t *Terminal) MenuOptionStatusHint(key, label, status, hint string) {
	status, hint = strings.TrimSpace(status), strings.TrimSpace(hint)
	if hint == "" {
		t.MenuOptionStatus(key, label, status)
		return
	}
	fmt.Fprintf(t.out, "  %s %s%s%s\n", t.menuKey(key, bold+blue), t.padDisplay(label, 18), t.padDisplay(status, 16), t.paint(gray, "-- "+hint))
}

func (t *Terminal) MenuChildOptionStatusHint(key, label, status, hint string, last bool) {
	branch := "├─"
	if last {
		branch = "└─"
	}
	status, hint = strings.TrimSpace(status), strings.TrimSpace(hint)
	fmt.Fprintf(t.out, "     %s %s %s%s%s\n", t.paint(gray, branch), t.menuKey(key, bold+blue), t.padDisplay(label, 12), t.padDisplay(status, 16), t.paint(gray, "-- "+hint))
}

func (t *Terminal) MenuTreeStatusHint(path []bool, key, label, status, hint string) {
	key, label, status, hint = strings.TrimSpace(key), strings.TrimSpace(label), strings.TrimSpace(status), strings.TrimSpace(hint)
	labelWidth := 18
	if len(path) > 0 {
		labelWidth = 12
	}
	var line strings.Builder
	line.WriteString(t.menuTreePrefix(path))
	if key != "" {
		line.WriteString(t.menuKey(key, bold+blue))
		line.WriteString(" ")
	}
	line.WriteString(t.padDisplay(label, labelWidth))
	line.WriteString(t.padDisplay(status, 16))
	if hint != "" {
		pad := 44 - displayWidth(line.String())
		if pad < 1 {
			pad = 1
		}
		line.WriteString(strings.Repeat(" ", pad))
		line.WriteString(t.paint(gray, "-- "+hint))
	}
	fmt.Fprintln(t.out, line.String())
}

func (t *Terminal) menuTreePrefix(path []bool) string {
	if len(path) == 0 {
		return "  "
	}
	var prefix strings.Builder
	prefix.WriteString("     ")
	for i, last := range path {
		if i < len(path)-1 {
			if last {
				prefix.WriteString("   ")
			} else {
				prefix.WriteString(t.paint(gray, "│") + "  ")
			}
			continue
		}
		branch := "├─"
		if last {
			branch = "└─"
		}
		prefix.WriteString(t.paint(gray, branch) + " ")
	}
	return prefix.String()
}

func (t *Terminal) MenuExit(key, label string) {
	fmt.Fprintf(t.out, "  %s %s\n", t.menuKey(key, bold+yellow), t.paint(dim, label))
}

func (t *Terminal) MenuSection(label string) {
	fmt.Fprintln(t.out, t.paint(bold, strings.TrimSpace(label)))
}

func (t *Terminal) MenuGroup(label, status string) {
	label, status = strings.TrimSpace(label), strings.TrimSpace(status)
	if status == "" {
		fmt.Fprintln(t.out, "  "+t.paint(bold, label))
		return
	}
	fmt.Fprintf(t.out, "  %s%s\n", t.padDisplay(t.paint(bold, label), 34), status)
}

func (t *Terminal) InvalidChoice() {
	fmt.Fprintln(t.out, t.paint(yellow, "无效选项，请重新输入"))
}

func (t *Terminal) LabelBadge(text string, positive bool) string {
	style := yellow
	if positive {
		style = green
	}
	return t.paint(style, "["+text+"]")
}

func (t *Terminal) Badge(status byte) string {
	switch status {
	case 'V':
		return t.LabelBadge("有效", true)
	case 'R':
		return t.paint(red, "[已吊销]")
	case 'E':
		return t.paint(yellow, "[已过期]")
	default:
		return t.paint(yellow, "[未知]")
	}
}

func (t *Terminal) PrintInfoCard(title string, fields ...CardField) {
	t.printCard(t.paint(bold+orange, strings.TrimSpace(title)), fields)
}
func (t *Terminal) PrintSuccessCard(title string, fields ...CardField) {
	t.printCard(t.paint(bold+green, strings.TrimSpace(title)), fields)
}
func (t *Terminal) PrintWarningCard(title string, fields ...CardField) {
	t.printCard(t.paint(bold+yellow, strings.TrimSpace(title)), fields)
}
func (t *Terminal) PrintDangerCard(title string, fields ...CardField) {
	t.printCard(t.paint(bold+red, strings.TrimSpace(title)), fields)
}
func (t *Terminal) printCard(title string, fields []CardField) {
	fmt.Fprintln(t.out, t.paint(bold+orange, "╭─ CAForge"))
	fmt.Fprintln(t.out, t.paint(orange, "│")+" "+title)
	for _, field := range fields {
		label, value := strings.TrimSpace(field.Label), strings.TrimSpace(field.Value)
		if label == "" {
			fmt.Fprintln(t.out, t.paint(orange, "│")+" "+value)
		} else {
			fmt.Fprintln(t.out, t.paint(orange, "│")+" "+t.paint(blue, label+"：")+value)
		}
		if detail := strings.TrimSpace(field.Detail); detail != "" {
			fmt.Fprintln(t.out, t.paint(orange, "│")+"   "+t.paint(gray, detail))
		}
	}
	fmt.Fprintln(t.out, t.paint(orange, "╰"+strings.Repeat("─", 46)))
}

func (t *Terminal) PrintField(label, value string) {
	fmt.Fprintln(t.out, t.paint(blue, strings.TrimSpace(label)+"：")+value)
}

func (t *Terminal) TableCell(text string, width int) string {
	padding := width - displayWidth(text)
	if padding < 0 {
		padding = 0
	}
	return text + strings.Repeat(" ", padding)
}

func (t *Terminal) Printf(format string, args ...any) { fmt.Fprintf(t.out, format, args...) }
func (t *Terminal) Info(s string)                     { fmt.Fprintln(t.out, t.paint(blue, "[信息]")+" "+s) }
func (t *Terminal) Success(s string)                  { t.Info(s) }
func (t *Terminal) Warning(s string)                  { fmt.Fprintln(t.out, t.paint(yellow, "[警告]")+" "+s) }
func (t *Terminal) Error(err error)                   { fmt.Fprintln(t.errOut, t.paint(red, "[错误]")+" "+err.Error()) }

func (t *Terminal) Ask(prompt string) (string, error) {
	fmt.Fprint(t.out, t.prompt(prompt))
	v, e := t.in.ReadString('\n')
	if e != nil && len(v) == 0 {
		return "", e
	}
	return strings.TrimSpace(v), nil
}

func (t *Terminal) prompt(prompt string) string {
	prompt = normalizePrompt(prompt)
	return t.paint(bold+orange, "❯ ") + t.paint(bold, prompt) + " "
}

func (t *Terminal) Password(prompt string) ([]byte, error) { return t.password(prompt) }
func (t *Terminal) Confirm(prompt string) (bool, error) {
	if !strings.Contains(strings.ToLower(prompt), "y/n") {
		prompt = strings.TrimSpace(prompt) + "（y/N）"
	}
	for {
		v, e := t.Ask(prompt)
		if e != nil {
			return false, e
		}
		v = strings.ToLower(strings.TrimSpace(v))
		switch v {
		case "y", "yes", "是":
			return true, nil
		case "", "n", "no", "否":
			return false, nil
		default:
			t.Warning("请输入 y 或 n")
		}
	}
}

func (t *Terminal) Pause() { t.PauseWithPrompt("按回车返回菜单…") }
func (t *Terminal) PauseWithPrompt(prompt string) {
	prompt = strings.TrimSpace(prompt)
	if strings.HasSuffix(prompt, "...") {
		prompt = strings.TrimSuffix(prompt, "...") + "…"
	}
	fmt.Fprintln(t.out)
	fmt.Fprint(t.out, t.paint(dim, prompt)+" ")
	_, _ = t.in.ReadString('\n')
	fmt.Fprintln(t.out)
}

func (t *Terminal) menuKey(key, style string) string {
	return t.paint(style, fmt.Sprintf("%-3s", strings.TrimSpace(key)))
}
func (t *Terminal) padDisplay(text string, width int) string {
	padding := width - displayWidth(text)
	if padding < 1 {
		padding = 1
	}
	return text + strings.Repeat(" ", padding)
}
func displayWidth(text string) int {
	width, inEscape := 0, false
	for _, current := range text {
		if inEscape {
			if current == 'm' {
				inEscape = false
			}
			continue
		}
		if current == '\x1b' {
			inEscape = true
			continue
		}
		if current >= 0x2e80 {
			width += 2
		} else {
			width++
		}
	}
	return width
}
func normalizePrompt(prompt string) string {
	prompt = strings.TrimSpace(prompt)
	if strings.HasSuffix(prompt, ":") {
		prompt = strings.TrimSuffix(prompt, ":") + "："
	}
	return prompt
}

func IsBack(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "0" || v == "q" || v == "exit"
}
