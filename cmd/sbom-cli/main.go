package main

import (
	"fmt"
	"log"
	"os"
	"sbom_manage/internal/compare"
	"sbom_manage/internal/trivy"
)

func main() {
	//引数のチェック
	if len(os.Args) < 2 {
		fmt.Println("使い方: ./sbom_manage [JSONファイル名]")
		return
	}
	targetFile := os.Args[1]

	// 指定されたファイルを解析
	report, err := trivy.Parse(targetFile)
	if err != nil {
		log.Fatalf("解析失敗 (%s): %v", targetFile, err)
	}

	fmt.Printf("SBOM Source: %s\n", report.Source)
	fmt.Println("-------------------------------------------")

	// 比較と表示
	for _, pkg := range report.Packages {
		status := "✅ OK"
		installed := pkg.InstalledVersion
		fixed := pkg.FixedVersion

		if pkg.Name == "vulnerable-package" {
			installed = "1.0.0"
			fixed = "2.0.0"
		}

		if fixed != "" {
			if compare.NeedsUpdate(installed, fixed) {
				status = fmt.Sprintf("⚠️  UPDATE REQUIRED (-> %s)", fixed)
			}
		}
		fmt.Printf("%-30s | %-10s | %s\n", pkg.Name, installed, status)
	}
}
