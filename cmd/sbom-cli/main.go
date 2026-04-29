package main

import (
	"fmt"
	"log"
	"os"
	"sbom_manage/internal/compare"
	"sbom_manage/internal/model"
	"sbom_manage/internal/scanner"
	"sbom_manage/internal/parser"
)

func main() {
	// 1. 引数チェック
	if len(os.Args) < 2 {
		fmt.Println("使い方: ./sbom_manage [CycloneDX_JSONファイル]")
		return
	}

	targetFile := os.Args[1]

	// 2. CycloneDXファイルの読み込み
	report, err := parser.ParseCycloneDX(targetFile)
	if err != nil {
		log.Fatalf("❌ ファイルの読み込みに失敗: %v", err)
	}

	fmt.Printf("📦 SBOM Source: %s\n", report.Source)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("%-35s | %-12s | %-20s | %s\n", "TARGET", "VERSION", "RESPONSIBLE", "STATUS")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	deptCounts := make(map[string]int)
	totalPackages := len(report.Packages)

	// 3. 各パッケージのリアルタイム診断とトリアージ
	for _, pkg := range report.Packages {
		v := model.Vulnerability{
			Purl:           pkg.PURL,
			Target:         pkg.Name,
			CurrentVersion: pkg.InstalledVersion,
		}

		// OSV APIから本物の脆弱性情報を取得
		if v.Purl != "" {
			// APIから FixedVersion, Score, CVE-ID を取得
			fixed, score, cveID, err := scanner.FetchVulnerabilityData(v.Purl)

			if err != nil {
				// 通信エラーなどの場合はログを出して次へ
				v.StatusMessage = "API Error"
			} else {
				v.FixedVersion = fixed
				v.Score = score
				v.Name = cveID
			}
		}


		scanner.TriageVulnerability(&v)

		// アップデートが必要かどうかの判定
		status := "✅ OK"
		if v.FixedVersion != "" {
			if compare.NeedsUpdate(v.CurrentVersion, v.FixedVersion) {
				status = fmt.Sprintf("⚠️  UPDATE (-> %s)", v.FixedVersion)
				// 脆弱性が確定したものだけ部署ごとに集計
				deptCounts[v.Responsible]++
			}
		}

		// 結果の1行表示
		fmt.Printf("%-35s | %-12s | %-20s | %s\n",
			truncate(v.Target, 35),
			v.CurrentVersion,
			v.Responsible,
			status)

		// CVE詳細がある場合はサブ行として表示
		if v.Name != "" && v.Score > 0 {
			fmt.Printf("   └── [%s] Score: %.1f (%s)\n", v.Name, v.Score, v.Responsible)
		}
	}

	// 4. 最終サマリーレポート
	printSummary(totalPackages, deptCounts)
}

// 統計サマリーの表示
func printSummary(total int, counts map[string]int) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("📊 最終診断レポート (全 %d コンポーネント)\n", total)

	totalIssues := 0
	for dept, count := range counts {
		fmt.Printf(" ・%-20s : %d 件\n", dept, count)
		totalIssues += count
	}

	if totalIssues == 0 {
		fmt.Println("\n✨ 検出された脆弱性はありません。")
	} else {
		fmt.Printf("\n📢 合計 %d 件の対応が必要です。担当部署は速やかに対応計画を策定してください。\n", totalIssues)
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// 表示
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
