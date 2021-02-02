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

var accountDb sync.Mutex
var inittabMaxLen = 3
var nameMaxLen = 255

func addUtmpEntry(username string, hostname string, remoteAddrV6 [4]int, ttyName string, inittabID string) error {
	if len(username) > nameMaxLen {
		return errors.New("username length exceeds OS limits")
	} else if len(hostname) > nameMaxLen {
		return errors.New("hostname length exceeds OS limits")
	} else if len(ttyName) > (int)(C.max_len_tty_name()-1) {
		return errors.New("tty name length exceeds OS limits")
	} else if len(inittabID) > inittabMaxLen {
		return errors.New("inittabID length exceeds OS limits")
	}

	var CUsername = C.CString(username)
	defer C.free(unsafe.Pointer(CUsername))
	var CHostname = C.CString(hostname)
	defer C.free(unsafe.Pointer(CHostname))
	var CTtyName = C.CString(ttyName)
	defer C.free(unsafe.Pointer(CTtyName))
	var CInittabID = C.CString(inittabID)
	defer C.free(unsafe.Pointer(CInittabID))

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
