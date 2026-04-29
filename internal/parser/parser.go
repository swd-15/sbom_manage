package parser

import (
	"encoding/json"
	"os"
	"sbom_manage/internal/model"
)


type cycloneDX struct {
	Metadata struct {
		Component struct {
			Name string `json:"name"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"components"`
}

func ParseCycloneDX(path string) (model.SBOM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.SBOM{}, err
	}

	var cd cycloneDX
	if err := json.Unmarshal(data, &cd); err != nil {
		return model.SBOM{}, err
	}

	var s model.SBOM
	s.Source = cd.Metadata.Component.Name
	for _, c := range cd.Components {
		s.Packages = append(s.Packages, model.Package{
			Name:             c.Name,
			InstalledVersion: c.Version,
			PURL:             c.PURL,
		})
	}
	return s, nil
}
