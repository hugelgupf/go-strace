// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package straceexpect_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/hugelgupf/go-strace/straceexpect"
	"github.com/u-root/u-root/pkg/uio/uiotest"
)

func prepareTestCmd(t *testing.T, cmd string) {
	if _, err := os.Stat(cmd); !os.IsNotExist(err) {
		if err != nil {
			t.Fatalf("Failed to find test program %q: %v", cmd, err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	w := uiotest.TestLineWriter(t, "make all")

	c := exec.CommandContext(ctx, "make", "all")
	c.Stdout = w
	c.Stderr = w
	c.Dir = "./test"
	if err := c.Run(); err != nil {
		t.Fatalf("make failed: %v", err)
	}
}

func TestSingleThreaded(t *testing.T) {
	prepareTestCmd(t, "./test/hello")

	var b bytes.Buffer
	cmd := exec.Command("./test/hello")
	cmd.Stdout = &b

	// Write strace logs to t.Logf.
	w := uiotest.TestLineWriter(t, "")

	_, err := straceexpect.Trace(w, cmd,
		// glibc's first action.
		straceexpect.Sysno(syscall.SYS_BRK),
		// What test/hello actually does.
		straceexpect.WriteEnter(1, "hello\n"),
		// Exit with status 0.
		straceexpect.ExitGroup(0),
	)
	if os.IsNotExist(err) {
		t.Errorf("Trace exited with error -- did you compile the test programs? (cd ./test && make all): %v", err)
	} else if err != nil {
		t.Errorf("Trace exited with error: %v", err)
	}
}

func TestMultiProcess(t *testing.T) {
	prepareTestCmd(t, "./test/fork")

	var b bytes.Buffer
	cmd := exec.Command("./test/fork")
	cmd.Stdout = &b

	// Write strace logs to t.Logf.
	w := uiotest.TestLineWriter(t, "")
	_, err := straceexpect.Trace(w, cmd)
	if os.IsNotExist(err) {
		t.Errorf("Trace exited with error -- did you compile the test programs? (cd ./test && make all): %v", err)
	} else if err != nil {
		t.Errorf("Trace exited with error: %v", err)
	}
}
