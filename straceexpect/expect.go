// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package straceexpect

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"syscall"

	"github.com/google/go-cmp/cmp"
	"github.com/hugelgupf/go-strace/strace"
	"github.com/hugelgupf/go-strace/straceprint"
)

type NoMatch struct {
	Err error
}

func (n NoMatch) Error() string {
	return fmt.Sprintf("no match: %v", n.Err)
}

func (n NoMatch) Unwrap() error {
	return n.Err
}

// Arg expects `arg` to be of a certain kind.
type Arg interface {
	Arg(t strace.Task, record *strace.TraceRecord, syscallArgNum int) error
}

type Int struct {
	Want int
}

func (ei Int) Arg(t strace.Task, record *strace.TraceRecord, syscallArgNum int) error {
	args := record.Syscall.Args
	got := args[syscallArgNum].Int64()

	if got != int64(ei.Want) {
		return &NoMatch{Err: fmt.Errorf("syscall arg got %d, want %d", got, ei.Want)}
	}
	return nil
}

// ReadWriteBuffer expects a char* at syscallArgNum and its length at
// syscallArgNum+1.
type ReadWriteBuffer struct {
	// Buf is the contents expected.
	Want string
}

func (eb ReadWriteBuffer) Arg(t strace.Task, record *strace.TraceRecord, syscallArgNum int) error {
	args := record.Syscall.Args
	addr := args[syscallArgNum].Pointer()
	size := args[syscallArgNum+1].SizeT()

	b := make([]byte, int(size))
	amt, err := t.Read(addr, b)
	if err != nil {
		return fmt.Errorf("%#x (error decoding string: %v)", addr, err)
	}

	got := string(b[:amt])
	if got != eb.Want {
		return &NoMatch{Err: fmt.Errorf("argument %d mismatch (-want, +got): %s", syscallArgNum, cmp.Diff(eb.Want, got))}
	}
	return nil
}

func Sysno(sysno int) *SyscallEnter {
	return &SyscallEnter{WantSysno: sysno}
}

func WriteEnter(wantFD int, wantBuf string) *SyscallEnter {
	return &SyscallEnter{
		WantSysno: syscall.SYS_WRITE,
		WantArgs: [6]Arg{
			&Int{Want: wantFD},
			&ReadWriteBuffer{Want: wantBuf},
		},
	}
}

func ExitGroup(wantStatus int) *SyscallEnter {
	return &SyscallEnter{
		WantSysno: syscall.SYS_EXIT_GROUP,
		WantArgs: [6]Arg{
			&Int{Want: wantStatus},
		},
	}
}

type SyscallEnter struct {
	WantSysno int
	WantArgs  [6]Arg
}

func (ese SyscallEnter) Event(t strace.Task, record *strace.TraceRecord) error {
	if record.Event != strace.SyscallEnter {
		return &NoMatch{Err: fmt.Errorf("event is %v, want syscall-enter", record.Event)}
	}
	if record.Syscall == nil {
		return fmt.Errorf("syscall structure is not filled for syscall event %#v", record)
	}
	if record.Syscall.Sysno != ese.WantSysno {
		return &NoMatch{Err: fmt.Errorf("syscall number is %d, want %d", record.Syscall.Sysno, ese.WantSysno)}
	}
	for i := range record.Syscall.Args {
		if ese.WantArgs[i] == nil {
			continue
		}
		var n *NoMatch
		if err := ese.WantArgs[i].Arg(t, record, i); errors.As(err, &n) {
			// Argument did not match expectations
			return &NoMatch{Err: fmt.Errorf("syscall %d event had argument error: %v", ese.WantSysno, err)}
		} else if err != nil {
			// Some other error?
			return err
		}
	}
	return nil
}

type Eventer interface {
	Event(t strace.Task, record *strace.TraceRecord) error
}

func Trace(logOut io.Writer, cmd *exec.Cmd, expecters ...Eventer) ([]*strace.TraceRecord, error) {
	traceChan := make(chan *strace.TraceRecord)
	done := make(chan error, 1)

	var expectIndex int
	expectTrace := func(t strace.Task, record *strace.TraceRecord) error {
		// We've gone through all expecters.
		if expectIndex == len(expecters) {
			return nil
		}

		var n *NoMatch
		if err := expecters[expectIndex].Event(t, record); errors.As(err, &n) {
			// This entry wasn't a match. Try the next record.
			return nil
		} else if err != nil {
			return err
		}
		// Expecter matched. Move forward.
		expectIndex++
		return nil
	}

	go func() {
		done <- strace.Trace(cmd, straceprint.PrintTraces(logOut), strace.RecordTraces(traceChan), expectTrace)
		close(traceChan)
	}()

	var events []*strace.TraceRecord
	for r := range traceChan {
		events = append(events, r)
	}

	if err := <-done; err != nil {
		return events, err
	}

	if expectIndex != len(expecters) {
		return events, fmt.Errorf("failed to find expected trace event %#v", expecters[expectIndex])
	}
	return events, nil
}
