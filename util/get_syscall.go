package util

import (
	"ebpf_exporter/util/constants"
	"fmt"
	"runtime"
)

func GetSyscall(syscallNum uint64) string {
	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "x86_64"
	case "386":
		arch = "x86"
	case "arm64":
		arch = "arm64"
	case "arm":
		arch = "arm"
	default:
		panic("unsupported arch")
	}

	var syscall string

	switch arch {
	case "x86_64":
		if name, ok := constants.X86_64_syscalls[syscallNum]; ok {
			syscall = name
		}
	case "x86":
		if name, ok := constants.X86_syscalls[syscallNum]; ok {
			syscall = name
		}
	case "arm":
		if name, ok := constants.ARM_syscalls[syscallNum]; ok {
			syscall = name
		}
	case "arm64":
		if name, ok := constants.ARM64_syscalls[syscallNum]; ok {
			syscall = name
		}
	}

	if syscall == "" {
		return fmt.Sprintf("unknown_syscall:%d", syscallNum)
	}

	return syscall
}
