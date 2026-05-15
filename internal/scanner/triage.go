package scanner

import (
	"strings"

	"sbom_manage/internal/config"
	"sbom_manage/internal/model"
)

func TriageVulnerability(v *model.Vulnerability, cfg *config.Config) {
	v.HasPatch = (v.FixedVersion != "")

	// APIから取得したSeverityがない場合のみスコアから補完
	if v.Severity == "" {
		if v.Score >= 9.0 {
			v.Severity = "CRITICAL"
		} else if v.Score >= 7.0 {
			v.Severity = "HIGH"
		} else if v.Score >= 4.0 {
			v.Severity = "MEDIUM"
		} else if v.Score > 0 {
			v.Severity = "LOW"
		}
	}

	// パッケージ名によるセキュリティ判定
	for _, keyword := range cfg.SecurityKeywords {
		if strings.Contains(strings.ToLower(v.Target), keyword) {
			v.Responsible = "Security CSIRT (High Priority)"
			return
		}
	}

	// スコア・深刻度による判定
	if v.Score >= 7.0 || v.Severity == "HIGH" || v.Severity == "CRITICAL" {
		v.Responsible = "Security CSIRT (High Priority)"
		return
	}

	// エコシステムによる判定
	eco := extractType(v.Purl)
	if dept, ok := cfg.EcosystemOwners[eco]; ok {
		v.Responsible = dept
	} else {
		v.Responsible = "Security CSIRT (Triage Required)"
	}
}

func extractType(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(purl, "pkg:"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
