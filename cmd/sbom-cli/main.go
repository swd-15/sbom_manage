package main

import (
	"fmt"
	"log"
	"os"
	"sbom_manage/internal/compare"
	"sbom_manage/internal/scanner"
	"sbom_manage/internal/trivy"
)

func main() {
	// 1. 引数チェック
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./sbom_manage [CycloneDX_JSON_File]")
		return
	}

	targetFile := os.Args[1]

	// 2. CycloneDXファイルの解析
	report, err := trivy.ParseCycloneDX(targetFile)
	if err != nil {
		log.Fatalf("❌ ファイルの読み込みに失敗しました: %v", err)
	}

	fmt.Printf("📦 SBOM Source: %s\n", report.Source)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	updateCount := 0

	// 3. 各パッケージの診断と表示
	for i, pkg := range report.Packages {
		// OSV APIを使ってリアルタイム診断
		if pkg.PURL != "" {
			fmt.Printf("🔍 診断中: %-30s", pkg.Name)

			fixed, err := scanner.FetchFixedVersion(pkg.PURL)
			if err != nil {
				fmt.Printf(" -> ⚠️ APIエラー")
			} else if fixed != "" {
				report.Packages[i].FixedVersion = fixed
			}
		}

		// バージョン比較
		status := "✅ OK"
		needsUpdate := false

		if report.Packages[i].FixedVersion != "" {
			if compare.NeedsUpdate(pkg.InstalledVersion, report.Packages[i].FixedVersion) {
				status = fmt.Sprintf("⚠️  UPDATE REQUIRED (-> %s)", report.Packages[i].FixedVersion)
				needsUpdate = true
				updateCount++
			}
		}

		// 診断中メッセージを上書きするように結果を表示
		fmt.Printf("\r%-40s | %-10s | %s\n", pkg.Name, pkg.InstalledVersion, status)

		// 脆弱性が見つかっている場合は、その詳細を表示（OSVから取得した情報を拡張する場合）
		for _, v := range pkg.Vulnerabilities {
			fmt.Printf("   └── [%s] %s\n", v.Severity, v.ID)
		}
	}

	// 4. サマリー表示
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("📊 診断完了: 合計 %d パッケージ中、%d 個に更新が必要です。\n",
		len(report.Packages), updateCount)
}
