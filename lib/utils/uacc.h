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
#include <utmpx.h>
#include <errno.h>

int UACC_GET_TIME_ERROR = 1;
int UACC_UTMP_MISSING_PERMISSIONS = 2;
int UACC_UTMP_WRITE_ERROR = 3;
int UACC_UTMP_READ_ERROR = 4;

// The max byte length of the C string representing the TTY name.
static int max_len_tty_name() {
    return __UT_LINESIZE;
}

static int upduacclog(struct utmpx *entry) {
    utmpname(_PATH_WTMP);
    setutxent();
    pututxline(entry);
    endutxent();
}

// Low level C function to add a new USER_PROCESS entry to the database.
// This function does not perform any argument validation.
static int uacc_add_utmp_entry(char *username, char *hostname, int32_t remote_addr_v6[4], char *tty_name) {
    utmpname(_PATH_UTMP);
    struct utmpx entry;
    entry.ut_type = USER_PROCESS;
    strcpy((char*) &entry.ut_line, tty_name + strlen("/dev/"));
    strcpy((char*) &entry.ut_id, tty_name + strlen("/dev/pts/"));
    entry.ut_pid = getpid();
    strcpy((char*) &entry.ut_host, hostname);
    strcpy((char*) &entry.ut_user, username);
    entry.ut_session = 1;
    struct timeval timestamp;
    int failed = gettimeofday(&timestamp, NULL);
    if (failed != 0) {
        return UACC_GET_TIME_ERROR;
    }
    entry.ut_tv.tv_sec = timestamp.tv_sec;
    entry.ut_tv.tv_usec = timestamp.tv_usec;
    memcpy(&entry.ut_addr_v6, &remote_addr_v6, sizeof(int32_t) * 4);
    setutxent();
    if (pututxline(&entry) == NULL) {
        return errno == EPERM || errno == EACCES ? UACC_UTMP_MISSING_PERMISSIONS : UACC_UTMP_WRITE_ERROR;
    }
    endutxent();
    upduacclog(&entry);
    return 0;
}

// Low level C function to mark a database entry as DEAD_PROCESS.
// This function does not perform string argument validation.
static int uacc_mark_utmp_entry_dead(char *tty_name) {
    utmpname(_PATH_UTMP);
    setutxent();
    struct utmpx line;
    strcpy((char*) &line.ut_line, tty_name);
    struct utmpx *entry_t = getutxline(&line);
    if (entry_t == NULL) {
        return UACC_UTMP_READ_ERROR;
    }
    struct utmpx entry;
    memcpy(&entry, entry_t, sizeof(struct utmpx));
    entry.ut_type = DEAD_PROCESS;
    setutxent();
    if (pututxline(&entry) == NULL) {
        return errno == EPERM ? UACC_UTMP_MISSING_PERMISSIONS : UACC_UTMP_WRITE_ERROR;
    }
    endutxent();
    upduacclog(&entry);
    return 0;
}

#endif