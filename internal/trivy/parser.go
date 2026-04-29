package trivy

import (
	"encoding/json"
	"os"
	"sbom_manage/internal/model"
)

// trivyJSON はTrivyの出力形式に合わせた内部用構造体
type trivyJSON struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Packages []struct {
			Name             string `json:"Name"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
		} `json:"Packages"`
	} `json:"Results"`
}

func Parse(path string) (model.SBOM, error) {
	var tj trivyJSON
	var s model.SBOM

	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}

	if err := json.Unmarshal(data, &tj); err != nil {
		return s, err
	}

	s.Source = tj.ArtifactName
	for _, res := range tj.Results {
		for _, pkg := range res.Packages {
			s.Packages = append(s.Packages, model.Package{
				Name:             pkg.Name,
				InstalledVersion: pkg.InstalledVersion,
				FixedVersion:     pkg.FixedVersion,
			})
		}
	}
	return s, nil
}
