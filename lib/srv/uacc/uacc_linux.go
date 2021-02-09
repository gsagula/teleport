// +build linux

/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package uacc

// #include <stdlib.h>
// #include "uacc.h"
import "C"

import (
	"encoding/binary"
	"net"
	"sync"
	"unsafe"

	"github.com/gravitational/trace"
)

// This module concerns itself with updating the user account database and log on nodes
// that a client connects to with an interactive session.

// Due to thread safety design in glibc we must serialize all access to the accounting database.
var accountDb sync.Mutex

// Max length of username and hostname as defined by glibc.
var nameMaxLen = 255

// Open writes a new entry to the utmp database with a tag of `USER_PROCESS`.
// This should be called when an interactive session is started.
//
// `username`: Name of the user the interactive session is running under.
// `hostname`: Name of the system the user is logged into.
// `remoteAddrV6`: IPv6 address of the remote host.
// `ttyName`: Name of the TTY without the `/dev/` prefix.
func Open(username, hostname string, remote net.IP, ttyName string) error {
	rawV6 := remote.To16()
	groupedV6 := [4]int32{}
	for i := range groupedV6 {
		groupedV6[i] = int32(binary.LittleEndian.Uint32(rawV6[i*4 : (i+1)*4]))
	}

	// String parameter validation.
	if len(username) > nameMaxLen {
		return trace.BadParameter("username length exceeds OS limits")
	} else if len(hostname) > nameMaxLen {
		return trace.BadParameter("hostname length exceeds OS limits")
	} else if len(ttyName) > (int)(C.max_len_tty_name()-1) {
		return trace.BadParameter("tty name length exceeds OS limits")
	}

	// Convert Go strings into C strings that we can pass over ffi.
	var CUsername = C.CString(username)
	defer C.free(unsafe.Pointer(CUsername))
	var CHostname = C.CString(hostname)
	defer C.free(unsafe.Pointer(CHostname))
	var CTtyName = C.CString(ttyName)
	defer C.free(unsafe.Pointer(CTtyName))

	// Convert IPv6 array into C integer format.
	var CInts = [4]C.int{}
	for i := 0; i < 4; i++ {
		CInts[i] = (C.int)(groupedV6[i])
	}

	accountDb.Lock()
	var status = C.uacc_add_utmp_entry(CUsername, CHostname, &CInts[0], CTtyName)
	accountDb.Unlock()

	switch status {
	case C.UACC_GET_TIME_ERROR:
		return trace.Errorf("InteractiveSessionOpened gettimeofday failed")
	case C.UACC_UTMP_MISSING_PERMISSIONS:
		return trace.Errorf("InteractiveSessionOpened missing permissions to write to utmp/wtmp")
	case C.UACC_UTMP_WRITE_ERROR:
		return trace.Errorf("InteractiveSessionOpened failed to add entry to utmp database")
	case C.UACC_UTMP_FAILED_OPEN:
		return trace.Errorf("InteractiveSessionOpened failed to open user account database")
	default:
		if status != 0 {
			return trace.Errorf("unknown error with code %d", status)
		}

		return nil
	}
}

// Close marks an entry in the utmp database as DEAD_PROCESS.
// This should be called when an interactive session exits.
//
// The `ttyName` parameter must be the name of the TTY without the `/dev/` prefix.
func Close(ttyName string) error {
	// String parameter validation.
	if len(ttyName) > (int)(C.max_len_tty_name()-1) {
		return trace.BadParameter("tty name length exceeds OS limits")
	}

	// Convert Go strings into C strings that we can pass over ffi.
	var CTtyName = C.CString(ttyName)
	defer C.free(unsafe.Pointer(CTtyName))

	accountDb.Lock()
	var status = C.uacc_mark_utmp_entry_dead(CTtyName)
	accountDb.Unlock()

	switch status {
	case C.UACC_GET_TIME_ERROR:
		return trace.Errorf("InteractiveSessionClosed gettimeofday failed")
	case C.UACC_UTMP_MISSING_PERMISSIONS:
		return trace.Errorf("InteractiveSessionClosed missing permissions to write to utmp/wtmp")
	case C.UACC_UTMP_WRITE_ERROR:
		return trace.Errorf("InteractiveSessionClosed failed to add entry to utmp database")
	case C.UACC_UTMP_READ_ERROR:
		return trace.Errorf("InteractiveSessionClosed failed to read and search utmp database")
	case C.UACC_UTMP_FAILED_OPEN:
		return trace.Errorf("InteractiveSessionClosed failed to open user account database")
	default:
		if status != 0 {
			return trace.Errorf("unknown error with code %d", status)
		}

		return nil
	}
}
