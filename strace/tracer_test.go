// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package strace_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/hugelgupf/go-strace/strace"
	"github.com/hugelgupf/go-strace/straceprint"
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

func runAndCollectTrace(t *testing.T, cmd *exec.Cmd) []*strace.TraceRecord {
	// Write strace logs to t.Logf.
	w := uiotest.TestLineWriter(t, "")
	traceChan := make(chan *strace.TraceRecord)
	done := make(chan error, 1)

	go func() {
		done <- strace.Trace(cmd, straceprint.PrintTraces(w), strace.RecordTraces(traceChan))
		close(traceChan)
	}()

	var events []*strace.TraceRecord
	for r := range traceChan {
		events = append(events, r)
	}

	if err := <-done; err != nil {
		if os.IsNotExist(err) {
			t.Errorf("Trace exited with error -- did you compile the test programs? (cd ./test && make all): %v", err)
		} else {
			t.Errorf("Trace exited with error: %v", err)
		}
	}
	return events
}

func TestSingleThreaded(t *testing.T) {
	prepareTestCmd(t, "./test/hello")

	var b bytes.Buffer
	cmd := exec.Command("./test/hello")
	cmd.Stdout = &b

	runAndCollectTrace(t, cmd)
}

func TestMultiProcess(t *testing.T) {
	prepareTestCmd(t, "./test/fork")

	var b bytes.Buffer
	cmd := exec.Command("./test/fork")
	cmd.Stdout = &b

	runAndCollectTrace(t, cmd)
}
