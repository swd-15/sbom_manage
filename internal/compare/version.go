package compare

import (
	"strconv"
	"strings"
)

func NeedsUpdate(installed, fixed string) bool {
	iv := parse(installed)
	fv := parse(fixed)
	if iv == nil || fv == nil {
		return false
	}
	for i := 0; i < 3; i++ {
		if fv[i] > iv[i] {
			return true
		}
		if fv[i] < iv[i] {
			return false
		}
	}
	return false
}

func parse(v string) []int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		for len(parts) < 3 {
			parts = append(parts, "0")
		}
	}
	result := make([]int, 3)
	for i := 0; i < 3; i++ {
		p := strings.Split(parts[i], "-")[0]
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		result[i] = n
	}
	return result
}
