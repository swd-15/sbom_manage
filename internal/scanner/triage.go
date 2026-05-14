package scanner

import (
	"strings"
	"sbom_manage/internal/model"
)

var defaultEcosystemMap = map[string]string{
	"golang": "Development Team",
	"npm":    "Development Team",
	"pypi":   "Development Team",
	"maven":  "Development Team",
	"cargo":  "Development Team",
	"deb":    "Infrastructure Team",
	"rpm":    "Infrastructure Team",
	"apk":    "Infrastructure Team",
}

var securityPackages = []string{
	"openssl", "libssl", "crypto", "jwt", "auth", "tls", "ssl",
}

func TriageVulnerability(v *model.Vulnerability) {
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

	// パッケージ名によるセキュリティ判定（エコシステム・スコアより優先）
	for _, keyword := range securityPackages {
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
	if dept, ok := defaultEcosystemMap[eco]; ok {
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
