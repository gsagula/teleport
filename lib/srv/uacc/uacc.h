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

#ifndef UACC_C
#define UACC_C

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <utmp.h>
#include <errno.h>

int UACC_GET_TIME_ERROR = 1;
int UACC_UTMP_MISSING_PERMISSIONS = 2;
int UACC_UTMP_WRITE_ERROR = 3;
int UACC_UTMP_READ_ERROR = 4;
int UACC_UTMP_FAILED_OPEN = 5;

// The max byte length of the C string representing the TTY name.
static int max_len_tty_name() {
    return UT_LINESIZE;
}

// Low level C function to add a new USER_PROCESS entry to the database.
// This function does not perform any argument validation.
static int uacc_add_utmp_entry(const char *username, const char *hostname, const int32_t remote_addr_v6[4], const char *tty_name) {
    struct utmp entry;
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
    errno = 0;
    setutent();
    if (errno != 0) {
        return UACC_UTMP_FAILED_OPEN;
    }
    if (pututline(&entry) == NULL) {
        return errno == EPERM || errno == EACCES ? UACC_UTMP_MISSING_PERMISSIONS : UACC_UTMP_WRITE_ERROR;
    }
    endutent();
    updwtmp(_PATH_WTMP, &entry);
    return 0;
}

// Low level C function to mark a database entry as DEAD_PROCESS.
// This function does not perform string argument validation.
static int uacc_mark_utmp_entry_dead(const char *tty_name) {
    errno = 0;
    setutent();
    if (errno != 0) {
        return UACC_UTMP_FAILED_OPEN;
    }
    struct utmp line;
    strcpy((char*) &line.ut_line, tty_name);
    struct utmp *entry_t = getutline(&line);
    if (entry_t == NULL) {
        return UACC_UTMP_READ_ERROR;
    }
    struct utmp entry;
    memcpy(&entry, entry_t, sizeof(struct utmp));
    entry.ut_type = DEAD_PROCESS;
    errno = 0;
    setutent();
    if (errno != 0) {
        return UACC_UTMP_FAILED_OPEN;
    }
    if (pututline(&entry) == NULL) {
        return errno == EPERM || errno == EACCES ? UACC_UTMP_MISSING_PERMISSIONS : UACC_UTMP_WRITE_ERROR;
    }
    endutent();
    updwtmp(_PATH_WTMP, &entry);
    return 0;
}

#endif
