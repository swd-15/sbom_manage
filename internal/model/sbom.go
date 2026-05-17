package model

type Vulnerability struct {
	Purl           string  `json:"purl"`
	Target         string  `json:"target"`
	CurrentVersion string  `json:"current_version"`
	FixedVersion   string  `json:"fixed_version"`
	Name           string  `json:"name"`
	Score          float64 `json:"score"`
	Severity       string  `json:"severity"`
	HasPatch       bool    `json:"has_patch"`
	Responsible    string  `json:"responsible"`
	StatusMessage  string  `json:"status_message,omitempty"`
}

type Package struct {
	Name             string  `json:"name"`
	InstalledVersion string  `json:"installed_version"`
	PURL             string  `json:"purl"`
}

type SBOM struct {
	Source   string
	Packages []Package
}
