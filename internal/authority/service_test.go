package authority_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"caforge/internal/authority"
	"caforge/internal/domain"
	"caforge/internal/revocation"
	"caforge/internal/store"
)

func TestAuthorityLifecycleManagement(t *testing.T) {
	repo, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Init(); err != nil {
		t.Fatal(err)
	}
	service := authority.New(repo)
	rootPassword := []byte("root passphrase")
	intermediatePassword := []byte("intermediate passphrase")
	root, err := service.CreateRoot(authority.CreateRootRequest{Name: "Test Root", Password: rootPassword})
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := service.CreateIntermediate(authority.CreateIntermediateRequest{
		ParentID: root.ID, Name: "Issuing CA", ParentPassword: rootPassword, Password: intermediatePassword,
	})
	if err != nil {
		t.Fatal(err)
	}

	rootMaterials, err := service.PublicMaterials(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(rootMaterials.ChainPEM, []byte("-----BEGIN CERTIFICATE-----")); got != 1 {
		t.Fatalf("root chain certificate count=%d", got)
	}
	intermediateMaterials, err := service.PublicMaterials(intermediate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(intermediateMaterials.ChainPEM, []byte("-----BEGIN CERTIFICATE-----")); got != 2 {
		t.Fatalf("intermediate chain certificate count=%d", got)
	}
	if !bytes.Equal(intermediateMaterials.RootCAPEM, rootMaterials.CertificatePEM) {
		t.Fatal("intermediate chain root does not match root CA certificate")
	}
	if err = service.Delete(root.ID); err == nil || !strings.Contains(err.Error(), "下级中间 CA") {
		t.Fatalf("root with child CA was deleted: %v", err)
	}

	if err = service.SetDisabled(root.ID, true); err != nil {
		t.Fatal(err)
	}
	if status, statusErr := service.Status(root.ID); statusErr != nil || status != "已停用" {
		t.Fatalf("root status=%q err=%v", status, statusErr)
	}
	if status, statusErr := service.Status(intermediate.ID); statusErr != nil || status != "父 CA 已停用" {
		t.Fatalf("intermediate status=%q err=%v", status, statusErr)
	}
	if err = service.Usable(intermediate.ID); err == nil || !strings.Contains(err.Error(), "父 CA 不可用") {
		t.Fatalf("disabled root did not block intermediate: %v", err)
	}
	if err = service.Select(root.ID); err == nil {
		t.Fatal("disabled root was selected for signing")
	}
	if err = service.SetDisabled(root.ID, false); err != nil {
		t.Fatal(err)
	}
	if err = service.Select(intermediate.ID); err != nil {
		t.Fatal(err)
	}

	if err = revocation.New(repo).Revoke(root.ID, intermediate.IssuerSerial, domain.CACompromise, rootPassword); err != nil {
		t.Fatal(err)
	}
	if status, statusErr := service.Status(intermediate.ID); statusErr != nil || status != "已吊销" {
		t.Fatalf("revoked intermediate status=%q err=%v", status, statusErr)
	}
	if err = service.Usable(intermediate.ID); err == nil || !strings.Contains(err.Error(), "已被父 CA 吊销") {
		t.Fatalf("revoked intermediate remained usable: %v", err)
	}

	if err = service.Delete(intermediate.ID); err != nil {
		t.Fatalf("delete empty intermediate: %v", err)
	}
	if _, err = os.Stat(filepath.Join(repo.Root(), "cas", intermediate.ID)); !os.IsNotExist(err) {
		t.Fatalf("intermediate directory still exists: %v", err)
	}
	if err = service.Delete(root.ID); err == nil || !strings.Contains(err.Error(), "签发记录") {
		t.Fatalf("root with audit record was deleted: %v", err)
	}

	emptyRoot, err := service.CreateRoot(authority.CreateRootRequest{Name: "Empty Root", Password: []byte("empty root passphrase")})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Delete(emptyRoot.ID); err != nil {
		t.Fatal(err)
	}
	if current, currentErr := repo.CurrentCA(); currentErr != nil || current != "" {
		t.Fatalf("deleted current CA was not cleared: current=%q err=%v", current, currentErr)
	}
}
