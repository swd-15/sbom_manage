package main

import (
	"fmt"
	"log"
	"sbom_manage/internal/compare"
    	"sbom_manage/internal/trivy"
)

func main() {

	report, err := trivy.Parse("testdata/trivy_sample.json")
	if err != nil {
		log.Fatalf("解析失敗: %v", err)
	}

	fmt.Printf("SBOM Source: %s\n", report.Source)
	fmt.Println("-------------------------------------------")

	for _, pkg := range report.Packages {
		status := "✅ OK"
		if pkg.FixedVersion != "" {
			if compare.NeedsUpdate(pkg.InstalledVersion, pkg.FixedVersion) {
				status = fmt.Sprintf("⚠️  UPDATE REQUIRED (-> %s)", pkg.FixedVersion)
			}
		}
		fmt.Printf("%-30s | %-10s | %s\n", pkg.Name, pkg.InstalledVersion, status)
	}
}
