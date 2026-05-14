package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempJSON(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "sbom-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestParseCycloneDX_Normal(t *testing.T) {
	json := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"components": [
			{"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
			{"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"}
		]
	}`
	path := writeTempJSON(t, json)

	sbom, err := ParseCycloneDX(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sbom.Packages) != 2 {
		t.Errorf("Packages count = %d, want 2", len(sbom.Packages))
	}
	if sbom.Packages[0].Name != "lodash" {
		t.Errorf("Packages[0].Name = %q, want %q", sbom.Packages[0].Name, "lodash")
	}
	if sbom.Packages[0].PURL != "pkg:npm/lodash@4.17.20" {
		t.Errorf("Packages[0].PURL = %q", sbom.Packages[0].PURL)
	}
}

func TestParseCycloneDX_SkipsNonPackageComponents(t *testing.T) {
	json := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"components": [
			{"type": "library", "name": "lodash",          "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
			{"type": "file",    "name": "/path/to/lock.json"}
		]
	}`
	path := writeTempJSON(t, json)

	sbom, err := ParseCycloneDX(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sbom.Packages) != 1 {
		t.Errorf("Packages count = %d, want 1 (type:file should be excluded)", len(sbom.Packages))
	}
	if sbom.Packages[0].Name != "lodash" {
		t.Errorf("残ったパッケージが想定外: %q", sbom.Packages[0].Name)
	}
}

func TestParseCycloneDX_EmptyComponents(t *testing.T) {
	json := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	path := writeTempJSON(t, json)

	sbom, err := ParseCycloneDX(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sbom.Packages) != 0 {
		t.Errorf("Packages count = %d, want 0", len(sbom.Packages))
	}
}

func TestParseCycloneDX_FileNotFound(t *testing.T) {
	_, err := ParseCycloneDX(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestParseCycloneDX_InvalidJSON(t *testing.T) {
	path := writeTempJSON(t, `{invalid json}`)
	_, err := ParseCycloneDX(path)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
