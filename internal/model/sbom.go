package model

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
	StatusMessage  string
}

type Package struct {
	Name             string
	InstalledVersion string
	PURL             string
}

type SBOM struct {
	Source   string
	Packages []Package
}
