package model

// Vulnerability は診断結果の最小単位
type Vulnerability struct {
	Purl           string
	Target         string
	CurrentVersion string
	FixedVersion   string
	Name           string
	Score          float64
	Severity       string
	HasPatch       bool
	Responsible    string
	StatusMessage  string // エラー表示用
}

// Package はパース直後のデータ構造
type Package struct {
	Name             string
	InstalledVersion string
	PURL             string
}

// SBOM はパース結果をまとめたもの
type SBOM struct {
	Source   string
	Packages []Package
}
