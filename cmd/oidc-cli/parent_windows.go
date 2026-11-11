package main

import "syscall"

func watchParent(pid int) (func() bool, func(), error) {
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return nil, nil, err
	}
	return func() bool {
		event, err := syscall.WaitForSingleObject(h, 0)
		return err == nil && event == syscall.WAIT_TIMEOUT
	}, func() { syscall.CloseHandle(h) }, nil
}
