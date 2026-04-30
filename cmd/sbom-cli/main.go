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
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./sbom_manage [CycloneDX_File]")
		return
	}

	targetFile := os.Args[1]
	report, err := parser.ParseCycloneDX(targetFile)
	if err != nil {
		log.Fatalf("❌ Error: %v", err)
	}

	fmt.Printf("SBOM: %s\n", targetFile)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("%-35s | %-12s | %-20s | %s\n", "TARGET", "VERSION", "RESPONSIBLE", "STATUS")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	deptCounts := make(map[string]int)

	for _, pkg := range report.Packages {
		v := model.Vulnerability{
			Purl:           pkg.PURL,
			Target:         pkg.Name,
			CurrentVersion: pkg.InstalledVersion,
		}

		if v.Purl != "" {
			fixed, score, cveID, severity, err := scanner.FetchVulnerabilityData(v.Purl)
			if err == nil {
				v.FixedVersion = fixed
				v.Score = score
				v.Name = cveID
				v.Severity = severity
			}
		}

		scanner.TriageVulnerability(&v)

		status := "✅ OK"
		if v.FixedVersion != "" && compare.NeedsUpdate(v.CurrentVersion, v.FixedVersion) {
			status = fmt.Sprintf("⚠️  UPDATE (-> %s)", v.FixedVersion)
			deptCounts[v.Responsible]++
		}

		// 表示
		fmt.Printf("%-35s | %-12s | %-20s | %s\n",
			truncate(v.Target, 35), v.CurrentVersion, v.Responsible, status)

		// 脆弱性がある場合のみ、深刻度ラベルとスコアを表示
		if v.Score > 0 {
			color := "\x1b[33m" // Yellow
			if v.Score >= 8.0 {
				color = "\x1b[31m" // Red
			}
			fmt.Printf("   └── %s[%s]%s ID: %s, Score: %.1f\n", color, v.Severity, "\x1b[0m", v.Name, v.Score)
		}
	}

	printSummary(deptCounts)
}

func printSummary(counts map[string]int) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Summary: Found Issues\n")
	for dept, count := range counts {
		fmt.Printf(" ・%-20s : %d\n", dept, count)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n-3] + "..."
}
