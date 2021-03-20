// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package straceprint

import (
	"fmt"
	"io"
	"os/exec"

	"github.com/hugelgupf/go-strace/strace"
	"golang.org/x/sys/unix"
)

func signalString(s unix.Signal) string {
	if 0 <= s && int(s) < len(signals) {
		return fmt.Sprintf("%s (%d)", signals[s], int(s))
	}
	return fmt.Sprintf("signal %d", int(s))
}

// PrintTraces prints every trace event to w.
func PrintTraces(w io.Writer) strace.EventCallback {
	return func(t strace.Task, record *strace.TraceRecord) error {
		switch record.Event {
		case strace.SyscallEnter:
			fmt.Fprintln(w, SysCallEnter(t, record.Syscall))
		case strace.SyscallExit:
			fmt.Fprintln(w, SysCallExit(t, record.Syscall))
		case strace.SignalExit:
			fmt.Fprintf(w, "PID %d exited from signal %s\n", record.PID, signalString(record.SignalExit.Signal))
		case strace.Exit:
			fmt.Fprintf(w, "PID %d exited from exit status %d (code = %d)\n", record.PID, record.Exit.WaitStatus, record.Exit.WaitStatus.ExitStatus())
		case strace.SignalStop:
			fmt.Fprintf(w, "PID %d got signal %s\n", record.PID, signalString(record.SignalStop.Signal))
		case strace.NewChild:
			fmt.Fprintf(w, "PID %d spawned new child %d\n", record.PID, record.NewChild.PID)
		}
		return nil
	}
}

// Strace traces and prints process events for `c` and its children to `out`.
func Strace(c *exec.Cmd, out io.Writer) error {
	return strace.Trace(c, PrintTraces(out))
}
