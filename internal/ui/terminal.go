package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type PasswordReader func(prompt string) ([]byte, error)
type Terminal struct {
	in       *bufio.Reader
	out      io.Writer
	color    bool
	password PasswordReader
}

func New(in io.Reader, out io.Writer, color bool, password PasswordReader) *Terminal {
	t := &Terminal{in: bufio.NewReader(in), out: out, color: color, password: password}
	if t.password == nil {
		t.password = t.linePassword
	}
	return t
}
func NewConsole() *Terminal {
	color := os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(os.Stdout.Fd()))
	t := New(os.Stdin, os.Stdout, color, nil)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.password = func(prompt string) ([]byte, error) {
			fmt.Fprint(os.Stdout, prompt)
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
func (t *Terminal) code(c, s string) string {
	if !t.color {
		return s
	}
	return "\x1b[" + c + "m" + s + "\x1b[0m"
}
func (t *Terminal) Clear() {
	if t.color {
		fmt.Fprint(t.out, "\x1b[2J\x1b[H")
	}
}
func (t *Terminal) Header(path string) {
	t.Clear()
	fmt.Fprintln(t.out, t.code("1;36", "CAForge")+"  "+t.code("2", path))
	fmt.Fprintln(t.out, t.code("2", strings.Repeat("─", 64)))
}

func (t *Terminal) HomeHeader(buildVersion string) {
	buildVersion = strings.TrimSpace(buildVersion)
	if buildVersion == "" {
		buildVersion = "dev"
	}
	t.Clear()
	fmt.Fprintln(t.out, t.code("1;36", "╭─ CAForge"))
	fmt.Fprintln(t.out, t.code("36", "│")+" 本地 CA 管理工具  "+t.code("30;42", " 版本 "+buildVersion+" "))
	fmt.Fprintln(t.out, t.code("36", "╰"+strings.Repeat("─", 62)))
}
func (t *Terminal) Printf(format string, args ...any) { fmt.Fprintf(t.out, format, args...) }
func (t *Terminal) Success(s string)                  { fmt.Fprintln(t.out, t.code("32", "[成功] ")+s) }
func (t *Terminal) Warning(s string)                  { fmt.Fprintln(t.out, t.code("33", "[警告] ")+s) }
func (t *Terminal) Error(err error)                   { fmt.Fprintln(t.out, t.code("31", "[错误] ")+err.Error()) }
func (t *Terminal) Badge(status byte) string {
	switch status {
	case 'V':
		return t.code("30;42", " 有效 ")
	case 'R':
		return t.code("37;41", " 已吊销 ")
	case 'E':
		return t.code("30;43", " 已过期 ")
	default:
		return t.code("2", " 未知 ")
	}
}
func (t *Terminal) Ask(prompt string) (string, error) {
	fmt.Fprint(t.out, prompt)
	v, e := t.in.ReadString('\n')
	if e != nil && len(v) == 0 {
		return "", e
	}
	return strings.TrimSpace(v), nil
}
func (t *Terminal) Password(prompt string) ([]byte, error) { return t.password(prompt) }
func (t *Terminal) Confirm(prompt string) (bool, error) {
	v, e := t.Ask(prompt + " [y/N]: ")
	if e != nil {
		return false, e
	}
	v = strings.ToLower(v)
	return v == "y" || v == "yes" || v == "是", nil
}
func IsBack(v string) bool { v = strings.ToLower(strings.TrimSpace(v)); return v == "0" || v == "q" }
