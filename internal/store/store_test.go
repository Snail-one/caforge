package store

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"caforge/internal/domain"
)

func TestPathTraversalAndTransactionRollback(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CADir("../escape"); err == nil {
		t.Fatal("path traversal accepted")
	}
	a := domain.Authority{ID: "test-ca", Name: "Test", CreatedAt: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	if err = s.CreateAuthority(a, []byte("cert"), []byte("secret")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(s.Root(), "cas/test-ca/serial"))
	if err != nil {
		t.Fatal(err)
	}
	wantErr := os.ErrInvalid
	if err = s.WithCA("test-ca", func(tx *Transaction) error {
		if _, e := tx.NextSerial(); e != nil {
			return e
		}
		return wantErr
	}); err != wantErr {
		t.Fatalf("got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(s.Root(), "cas/test-ca/serial"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("serial was not rolled back: %q -> %q", before, after)
	}
	keyInfo, err := os.Stat(filepath.Join(s.Root(), "cas/test-ca/private/ca.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("key mode %o", keyInfo.Mode().Perm())
	}
	rootInfo, err := os.Stat(s.Root())
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode().Perm() != 0700 {
		t.Fatalf("root mode %o", rootInfo.Mode().Perm())
	}
}

func TestConcurrentSerialAllocation(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	a := domain.Authority{ID: "concurrent-ca", Name: "Concurrent", CreatedAt: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	if err = s.CreateAuthority(a, []byte("cert"), []byte("secret")); err != nil {
		t.Fatal(err)
	}
	const workers = 16
	serials := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.WithCA(a.ID, func(tx *Transaction) error {
				n, e := tx.NextSerial()
				if e == nil {
					serials <- n.Text(16)
				}
				return e
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(serials)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for serial := range serials {
		if seen[serial] {
			t.Fatalf("duplicate serial %s", serial)
		}
		seen[serial] = true
	}
	if len(seen) != workers {
		t.Fatalf("got %d serials", len(seen))
	}
}

func TestOpenSSLIndexRoundTrip(t *testing.T) {
	revoked := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	entries := []IndexEntry{{Status: 'V', Expires: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), Serial: "1000", Filename: "unknown", Subject: "/CN=valid"}, {Status: 'R', Expires: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), RevokedAt: &revoked, Reason: domain.KeyCompromise, Serial: "1001", Filename: "unknown", Subject: "/CN=revoked"}}
	parsed, err := ParseIndex(EncodeIndex(entries))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 || parsed[1].Reason != domain.KeyCompromise || parsed[1].RevokedAt == nil {
		t.Fatalf("bad round trip: %#v", parsed)
	}
}
