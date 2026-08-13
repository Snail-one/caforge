package selfupdate

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRunDownloadsAndExecutesScript(t *testing.T) {
	client := testClient(http.StatusOK, "#!/bin/sh\nprintf 'update-called\\n'\n")
	var output bytes.Buffer
	if err := run(client, "https://example.invalid/install.sh", strings.NewReader(""), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if output.String() != "update-called\n" {
		t.Fatalf("意外的脚本输出：%q", output.String())
	}
}

func TestRunPassesUninstallArgument(t *testing.T) {
	client := testClient(http.StatusOK, "#!/bin/sh\nprintf '%s\\n' \"$1\"\n")
	var output bytes.Buffer
	if err := run(client, "https://example.invalid/install.sh", strings.NewReader(""), &output, &bytes.Buffer{}, "--uninstall"); err != nil {
		t.Fatal(err)
	}
	if output.String() != "--uninstall\n" {
		t.Fatalf("卸载参数未透传：%q", output.String())
	}
}

func TestRunRejectsUnexpectedOrOversizedContent(t *testing.T) {
	for name, body := range map[string]string{
		"invalid":   "not a shell script",
		"oversized": "#!/bin/sh\n" + strings.Repeat("x", maxScriptSize),
	} {
		t.Run(name, func(t *testing.T) {
			err := run(testClient(http.StatusOK, body), "https://example.invalid/install.sh", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil {
				t.Fatal("应拒绝无效管理脚本")
			}
		})
	}
}

func TestRunReportsHTTPFailure(t *testing.T) {
	err := run(testClient(http.StatusNotFound, "missing"), "https://example.invalid/install.sh", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("应返回 HTTP 错误，得到：%v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testClient(status int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    status,
			Status:        http.StatusText(status),
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Header:        make(http.Header),
			Request:       request,
		}, nil
	})}
}
