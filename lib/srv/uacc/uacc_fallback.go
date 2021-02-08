// +build !linux

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

// This is a shim module that compiles on operating systems where we don't support user accounting via utmp/wtmp.

package uacc

import "net"

func Open(username, hostname string, remote net.IP, ttyName string) error {
	return nil
}

func Close(ttyName string) error {
	return nil
}
