package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sbom_manage/internal/compare"
	"sbom_manage/internal/config"
	"sbom_manage/internal/model"
	"sbom_manage/internal/parser"
	"sbom_manage/internal/scanner"
	"sbom_manage/internal/store"
	"strings"
	"time"
)

func main() {
	configPath := flag.String("config", "config.yaml", "設定ファイルのパス")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}

	st, err := store.DefaultStore()
	if err != nil {
		log.Fatalf("❌ ストア初期化エラー: %v", err)
	}

	switch args[0] {
	case "scan":
		os.Exit(cmdScan(args[1:], st, cfg))
	case "history":
		cmdHistory(st)
	case "status":
		cmdStatus(args[1:], st)
	default:
		fmt.Fprintf(os.Stderr, "❌ 不明なコマンド: %q\n\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func cmdScan(args []string, st store.Store, cfg *config.Config) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sbom_manage scan <sbom.json>")
		os.Exit(1)
	}
	targetFile := args[0]

	report, err := parser.ParseCycloneDX(targetFile)
	if err != nil {
		log.Fatalf("❌ Error: %v", err)
	}

	fmt.Printf("SBOM: %s\n", targetFile)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("%-35s | %-12s | %-20s | %s\n", "TARGET", "VERSION", "RESPONSIBLE", "STATUS")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	deptCounts := make(map[string]int)
	var vulns []model.Vulnerability

	for _, pkg := range report.Packages {
		v := model.Vulnerability{
			Purl:           pkg.PURL,
			Target:         pkg.Name,
			CurrentVersion: pkg.InstalledVersion,
		}

		if v.Purl != "" {
			fixed, score, cveID, severity, err := scanner.FetchVulnerabilityData(v.Purl)
			if err != nil {
				fmt.Printf("%-35s | %-12s | %-20s | ⚠️  SCAN FAILED (%v)\n",
					truncate(v.Target, 35), v.CurrentVersion, "—", err)
				continue
			}
			v.FixedVersion = fixed
			v.Score = score
			v.Name = cveID
			v.Severity = severity
		}

		scanner.TriageVulnerability(&v, cfg)

		statusLabel := "✅ OK"
		if v.FixedVersion != "" && compare.NeedsUpdate(v.CurrentVersion, v.FixedVersion) {
			statusLabel = fmt.Sprintf("⚠️  UPDATE (-> %s)", v.FixedVersion)
			deptCounts[v.Responsible]++
			if vs, _ := st.GetStatus(v.Name); vs != nil {
				statusLabel += fmt.Sprintf(" [%s]", vs.Status)
			}
			vulns = append(vulns, v)
		}

		fmt.Printf("%-35s | %-12s | %-20s | %s\n",
			truncate(v.Target, 35), v.CurrentVersion, v.Responsible, statusLabel)

		if v.Score > 0 {
			color := "\x1b[33m"
			if v.Score >= 8.0 {
				color = "\x1b[31m"
			}
			fmt.Printf("   └── %s[%s]\x1b[0m ID: %s, Score: %.1f\n", color, v.Severity, v.Name, v.Score)
		}
	}

	printSummary(deptCounts)

	scanID := fmt.Sprintf("%d", time.Now().UnixNano())
	if err := st.SaveScan(store.ScanRecord{
		ID:        scanID,
		ScannedAt: time.Now(),
		Source:    targetFile,
		Vulns:     vulns,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  スキャン履歴の保存に失敗: %v\n", err)
	} else {
		fmt.Printf("\n💾 スキャン結果を保存しました (ID: %s)\n", scanID)
	}

	// CRITICAL/HIGHがあればexit 1
	for _, v := range vulns {
		if v.Score >= 7.0 || v.Severity == "HIGH" || v.Severity == "CRITICAL" {
			fmt.Fprintln(os.Stderr, "\n❌ High以上の脆弱性が検出されました")
			return 1
		}
	}
	return 0
}

func cmdHistory(st store.Store) {
	records, err := st.ListScans()
	if err != nil {
		log.Fatalf("❌ 履歴取得エラー: %v", err)
	}
	if len(records) == 0 {
		fmt.Println("スキャン履歴はありません。")
		return
	}

	statuses, _ := st.ListStatuses()
	statusMap := make(map[string]store.ScanStatus)
	for _, vs := range statuses {
		statusMap[vs.CveID] = vs.Status
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("%-20s | %-30s | %s\n", "DATE", "SOURCE", "VULNS")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	for _, r := range records {
		date := r.ScannedAt.Format("2006-01-02 15:04:05")
		fmt.Printf("%-20s | %-30s | %d件\n", date, truncate(r.Source, 30), len(r.Vulns))
		for _, v := range r.Vulns {
			s := statusMap[v.Name]
			if s == "" {
				s = store.StatusOpen
			}
			color := statusColor(s)
			fmt.Printf("   └── [%s%s\x1b[0m] %s (%s)\n", color, s, v.Name, v.Target)
		}
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func cmdStatus(args []string, st store.Store) {
	if len(args) == 0 {
		listAllStatuses(st)
		return
	}
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: sbom_manage status <CVE-ID> <open|in-progress|done> [note]")
		os.Exit(1)
	}

	cveID := args[0]
	newStatus := store.ScanStatus(args[1])
	note := ""
	if len(args) >= 3 {
		note = strings.Join(args[2:], " ")
	}

	switch newStatus {
	case store.StatusOpen, store.StatusInProgress, store.StatusDone:
	default:
		fmt.Fprintf(os.Stderr, "❌ 不正なステータス: %q (open / in-progress / done)\n", newStatus)
		os.Exit(1)
	}

	if err := st.SetStatus(cveID, newStatus, note); err != nil {
		log.Fatalf("❌ ステータス更新エラー: %v", err)
	}
	fmt.Printf("✅ %s のステータスを [%s] に更新しました\n", cveID, newStatus)
	if note != "" {
		fmt.Printf("   メモ: %s\n", note)
	}
}

func listAllStatuses(st store.Store) {
	statuses, err := st.ListStatuses()
	if err != nil {
		log.Fatalf("❌ ステータス取得エラー: %v", err)
	}
	if len(statuses) == 0 {
		fmt.Println("対応状況の記録はありません。")
		return
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("%-20s | %-12s | %-20s | %s\n", "CVE-ID", "STATUS", "UPDATED", "NOTE")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	for _, vs := range statuses {
		color := statusColor(vs.Status)
		updated := vs.UpdatedAt.Format("2006-01-02 15:04")
		fmt.Printf("%-20s | %s%-12s\x1b[0m | %-20s | %s\n",
			vs.CveID, color, vs.Status, updated, vs.Note)
	}
}

func printUsage() {
	fmt.Print(`Usage: sbom_manage <command> [args]

Options:
  -config <path>   設定ファイルのパスを指定（デフォルト: ./config.yaml）

Commands:
  scan <sbom.json>                          SBOMをスキャンして結果をDBに保存
  history                                   過去のスキャン履歴を表示
  status                                    全脆弱性の対応状況を表示
  status <CVE-ID> <open|in-progress|done>   対応状況を更新
  status <CVE-ID> <status> <note>           メモ付きで更新

Examples:
  ./sbom_manage scan testdata/testfailed.json
  ./sbom_manage -config /etc/sbom_manage/config.yaml scan sbom.json
  ./sbom_manage history
  ./sbom_manage status CVE-2021-44228 in-progress "担当者アサイン済み"
  ./sbom_manage status CVE-2021-44228 done "4.17.21にアップデート完了"
  ./sbom_manage status
`)
}

func printSummary(counts map[string]int) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Summary: Found Issues")
	for dept, count := range counts {
		fmt.Printf(" ・%-20s : %d\n", dept, count)
	}
}

func statusColor(s store.ScanStatus) string {
	switch s {
	case store.StatusOpen:
		return "\x1b[31m"
	case store.StatusInProgress:
		return "\x1b[33m"
	case store.StatusDone:
		return "\x1b[32m"
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
