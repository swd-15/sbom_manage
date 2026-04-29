package scanner

import (
	"strings"
	"sbom_manage/internal/model"
)

var defaultEcosystemMap = map[string]string{
	"golang":   "Development Team",
	"npm":      "Development Team",
	"pypi":     "Development Team",
	"maven":    "Development Team",
	"cargo":    "Development Team",
	"deb":      "Infrastructure Team",
	"rpm":      "Infrastructure Team",
	"apk":      "Infrastructure Team",
}

func TriageVulnerability(v *model.Vulnerability) {
	// 1. パッチ有無の自動設定
	v.HasPatch = (v.FixedVersion != "")

	// 2. 責任部署の判定 (優先順位: Score > Map > Default)
	if v.Score >= 8.0 {
		v.Responsible = "Security CSIRT (High Priority)"
		return
	}

	eco := extractType(v.Purl)

	if dept, ok := defaultEcosystemMap[eco]; ok {
		v.Responsible = dept
	} else {
		// 判定不能なものはセキュリティチームへ
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
