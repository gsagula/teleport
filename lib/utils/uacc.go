/*
Copyright 2019 Gravitational, Inc.

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

package utils

// #include <stdlib.h>
// #include "uacc.h"
import "C"

import (
	"errors"
	"sync"
	"unsafe"
)

// Due to thread safety design in glibc we must serialize all access to the accounting database.
var accountDb sync.Mutex

// Max length of the inittab ID as defined by glibc.
var inittabMaxLen = 3

// Max length of username and hostname as defined by glibc.
var nameMaxLen = 255

// Writes a new entry to the utmp database with a tag of `USER_PROCESS`.
// This should be called when an interactive session is started.
//
// `username`: Name of the user the interactive session is running under.
// `hostname`: Name of the system the user is logged into.
// `remoteAddrV6`: IPv6 address of the remote host.
// `ttyName`: Name of the TTY without the `/dev/` prefix.
// `inittabID`: The ID of the inittab entry.
func addUtmpEntry(username string, hostname string, remoteAddrV6 [4]int, ttyName string, inittabID string) error {
	// String parameter validation.
	if len(username) > nameMaxLen {
		return errors.New("username length exceeds OS limits")
	} else if len(hostname) > nameMaxLen {
		return errors.New("hostname length exceeds OS limits")
	} else if len(ttyName) > (int)(C.max_len_tty_name()-1) {
		return errors.New("tty name length exceeds OS limits")
	} else if len(inittabID) > inittabMaxLen {
		return errors.New("inittabID length exceeds OS limits")
	}

	// Convert Go strings into C strings that we can pass over ffi.
	var CUsername = C.CString(username)
	defer C.free(unsafe.Pointer(CUsername))
	var CHostname = C.CString(hostname)
	defer C.free(unsafe.Pointer(CHostname))
	var CTtyName = C.CString(ttyName)
	defer C.free(unsafe.Pointer(CTtyName))
	var CInittabID = C.CString(inittabID)
	defer C.free(unsafe.Pointer(CInittabID))

	// Convert IPv6 array into C integer format.
	var CInts = [4]C.int{}
	for i := 0; i < 4; i++ {
		CInts[i] = (C.int)(remoteAddrV6[i])
	}

	accountDb.Lock()
	var status = C.uacc_add_utmp_entry(CUsername, CHostname, (*C.int)(&CInts[0]), CTtyName, CInittabID)
	accountDb.Unlock()

	if status != 0 {
		return errors.New("failed to add entry to utmp database")
	}

	return nil
}

// This function marks an entry in the utmp database as DEAD_PROCESS.
// This should be called when an interactive session exits.
//
// The `ttyName` parameter must be the name of the TTY without the `/dev/` prefix.
func markUtmpEntryDead(ttyName string) error {
	// String parameter validation.
	if len(ttyName) > (int)(C.max_len_tty_name()-1) {
		return errors.New("tty name length exceeds OS limits")
	}

	// Convert Go strings into C strings that we can pass over ffi.
	var CTtyName = C.CString(ttyName)
	defer C.free(unsafe.Pointer(CTtyName))

	accountDb.Lock()
	var status = C.uacc_mark_utmp_entry_dead(CTtyName)
	accountDb.Unlock()

	if status != 0 {
		return errors.New("failed to modify utmp entry in database")
	}

	return nil
}
