package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestLoad_Normal(t *testing.T) {
	yaml := `
ecosystem_owners:
  npm: "Frontend Team"
  pypi: "Backend Team"
security_keywords:
  - openssl
  - jwt
`
	path := writeTempConfig(t, yaml)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.EcosystemOwners["npm"] != "Frontend Team" {
		t.Errorf("npm = %q, want %q", cfg.EcosystemOwners["npm"], "Frontend Team")
	}
	if len(cfg.SecurityKeywords) != 2 {
		t.Errorf("SecurityKeywords count = %d, want 2", len(cfg.SecurityKeywords))
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "invalid: [yaml")
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if len(cfg.EcosystemOwners) == 0 {
		t.Error("EcosystemOwners should not be empty")
	}
	if len(cfg.SecurityKeywords) == 0 {
		t.Error("SecurityKeywords should not be empty")
	}
	if cfg.EcosystemOwners["npm"] == "" {
		t.Error("npm owner should be set")
	}
}
