package compare

import (
	"github.com/Masterminds/semver/v3"
)

func NeedsUpdate(installed, fixed string) bool {
	vInst, err1 := semver.NewVersion(installed)
	vFix, err2 := semver.NewVersion(fixed)

	// バージョンが正しく読み込めない場合は更新不要とする
	if err1 != nil || err2 != nil {
		return false
	}

	// 修正版がインストール版より大きければ更新必要
	return vFix.GreaterThan(vInst)
}
