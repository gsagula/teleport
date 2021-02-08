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

package srv

// #include <unistd.h>
import "C"
import (
	"errors"
	"os"
)

// TtyName fetches the OS TTY name for a file descriptor.
// This returns an error if the file descriptor is not associated with a TTY.
func TtyName(file *os.File) (*string, error) {
	fd := file.Fd()
	ttyNameBuf := [256]C.char{}
	status := C.ttyname_r((C.int)(fd), &ttyNameBuf[0], 256)
	if status != 0 {
		return nil, errors.New("failed to fetch tty name")
	}
	ttyName := C.GoString(&ttyNameBuf[0])
	return &ttyName, nil
}
