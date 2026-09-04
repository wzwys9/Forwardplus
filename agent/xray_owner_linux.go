//go:build linux

package main

import (
	"os"
	"syscall"
)

func xrayPathOwnerAllowed(info os.FileInfo, final bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	owner := int(stat.Uid)
	effectiveUID := os.Geteuid()
	if final {
		return owner == effectiveUID
	}
	return owner == 0 || owner == effectiveUID
}
