package model

// SBOM はツール共通のデータ構造
type SBOM struct {
	Source   string
	Packages []Package
}

// Package は個別のライブラリ情報
type Package struct {
	Name             string
	InstalledVersion string
	FixedVersion     string // 脆弱性が修正されたバージョン
}
