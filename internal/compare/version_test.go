package compare

import "testing"

func TestNeedsUpdate(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		fixed     string
		want      bool
	}{
		// 更新が必要なケース
		{"patch更新あり", "4.17.20", "4.17.21", true},
		{"minor更新あり", "1.2.0", "1.3.0", true},
		{"major更新あり", "1.0.0", "2.0.0", true},

		// 更新不要なケース
		{"同一バージョン", "4.17.21", "4.17.21", false},
		{"インストール済みが新しい", "5.0.0", "4.17.21", false},

		// 異常値ケース
		{"installedが不正", "invalid", "1.0.0", false},
		{"fixedが不正", "1.0.0", "invalid", false},
		{"両方空", "", "", false},
		{"vプレフィックスあり", "v1.2.3", "v1.2.4", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NeedsUpdate(tt.installed, tt.fixed)
			if got != tt.want {
				t.Errorf("NeedsUpdate(%q, %q) = %v, want %v",
					tt.installed, tt.fixed, got, tt.want)
			}
		})
	}
}
