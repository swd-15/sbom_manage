package parser

import (
	"encoding/json"
	"os"
	"sbom_manage/internal/model"
)

// CycloneDX の全体構造
type CycloneDX struct {
	BOMFormat  string      `json:"bomFormat"`
	SpecVersion string     `json:"specVersion"`
	Components []Component `json:"components"`
}

// 個別のパッケージ構造
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

func ParseCycloneDX(filePath string) (*model.SBOM, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var cd CycloneDX
	if err := json.Unmarshal(file, &cd); err != nil {
		return nil, err
	}

	// model.SBOM 形式に変換
	report := &model.SBOM{
		Source: filePath,
	}

	for _, c := range cd.Components {
		report.Packages = append(report.Packages, model.Package{
			Name:             c.Name,
			InstalledVersion: c.Version,
			PURL:             c.PURL,
		})
	}

	return report, nil
}
