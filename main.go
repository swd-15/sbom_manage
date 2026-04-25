package main

import (
	"fmt"
)

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
}

func main() {
	v := Vulnerability{
		Purl:           "pkg:pypi/python@3.9.0",
		Target:         "Python",
		CurrentVersion: "3.9.0",
		FixedVersion:   "3.9.19",
		Name:           "CVE-2024-XXXX",
		Score:          7.5,
		Severity:       "High",
		HasPatch:       true,
		Responsible:    "開発チーム",
	}

	fmt.Println("--- SBOM Management Tool Alpha ---")
	fmt.Printf("脆弱性名: %s\n", v.Name)
	fmt.Printf("対象: %s (%s)\n", v.Target, v.Purl)
	fmt.Printf("状態: %s -> %s (修正済み)\n", v.CurrentVersion, v.FixedVersion)
	fmt.Printf("深刻度: [%s] (Score: %.1f)\n", v.Severity, v.Score)
	fmt.Printf("対応担当: %s\n", v.Responsible)
	fmt.Println("----------------------------------")
}
