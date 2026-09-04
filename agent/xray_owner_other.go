//go:build !linux

package main

import "os"

func xrayPathOwnerAllowed(_ os.FileInfo, _ bool) bool {
	return true
}
