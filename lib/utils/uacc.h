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

#ifndef UACC_H
#define UACC_H

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <utmp.h>

static int max_len_tty_name() {
    return UT_LINESIZE;
}

static int uacc_add_utmp_entry(char *username, char *hostname, int32_t remote_addr_v6[4], char *tty_name, char* inittabId) {
    struct utmp entry;
    entry.ut_type = USER_PROCESS;
    strcpy((char*) &entry.ut_line, tty_name);
    strcpy((char*) &entry.ut_id, inittabId);
    entry.ut_pid = getpid();
    strcpy((char*) &entry.ut_host, hostname);
    strcpy((char*) &entry.ut_user, username);
    entry.ut_session = 0;

    struct timeval timestamp;
    int failed = gettimeofday(&timestamp, NULL);

    if (failed != 0) {
        return 1;
    }

    entry.ut_tv.tv_sec = timestamp.tv_sec;
    entry.ut_tv.tv_usec = timestamp.tv_usec;
    memcpy(&entry.ut_addr_v6, &remote_addr_v6, sizeof(int32_t) * 4);

    setutent();
    if (pututline(&entry) == NULL) {
        return 1;
    }
    endutent();
    updwtmp(_PATH_WTMP, &entry);
    return 0;
}

static int uacc_mark_utmp_entry_dead(char *tty_name) {
    setutent();
    struct utmp line;
    strcpy((char*) &line.ut_line, tty_name);
    struct utmp entry;
    struct utmp *bptr = &entry;
    int status = getutline_r(&line, &entry, &bptr);
    if (status != 0) {
        return 1;
    }
    entry.ut_type = DEAD_PROCESS;
    setutent();
    if (pututline(&entry) == NULL) {
        return 1;
    }
    endutent();
    updwtmp(_PATH_WTMP, &entry);
    return 0;
}

#endif