// Copyright 2018 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package strace

import (
	"golang.org/x/sys/unix"
)

const archWidth = 64

// FillArgs pulls the correct registers to populate system call arguments
// and the system call number into a TraceRecord. Note that the system
// call number is not technically an argument. This is good, in a sense,
// since it makes the function arguments end up in "the right place"
// from the point of view of the caller. The performance improvement is
// negligible, as you can see by a look at the GNU runtime.
func (s *SyscallEvent) FillArgs() {
	s.Args = SyscallArguments{
		{uintptr(s.Regs.Rdi)},
		{uintptr(s.Regs.Rsi)},
		{uintptr(s.Regs.Rdx)},
		{uintptr(s.Regs.R10)},
		{uintptr(s.Regs.R8)},
		{uintptr(s.Regs.R9)}}
	s.Sysno = int(uint32(s.Regs.Orig_rax))
}

// FillRet fills the TraceRecord with the result values from the registers.
func (s *SyscallEvent) FillRet() {
	s.Ret = [2]SyscallArgument{{uintptr(s.Regs.Rax)}, {uintptr(s.Regs.Rdx)}}
	if errno := int(s.Regs.Rax); errno < 0 {
		s.Errno = unix.Errno(-errno)
	}
}
