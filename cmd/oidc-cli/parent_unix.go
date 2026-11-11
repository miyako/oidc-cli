//go:build !windows

package main

import "syscall"

func watchParent(pid int) (func() bool, func(), error) {
	err := syscall.Kill(pid, 0)
	if err != nil {
		return nil, nil, err
	}
	return func() bool { return syscall.Kill(pid, 0) == nil }, func() {}, nil
}
