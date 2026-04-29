package model

type SBOM struct {
	Source   string
	Packages []Package
}

type Package struct {
	Name             string
	InstalledVersion string
	FixedVersion     string
	PURL             string
	Vulnerabilities  []Vulnerability
}

type Vulnerability struct {
	ID       string
	Severity string
}
