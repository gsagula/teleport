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

int UACC_UTMP_MISSING_PERMISSIONS = 1;
int UACC_UTMP_WRITE_ERROR = 2;
int UACC_UTMP_READ_ERROR = 3;
int UACC_UTMP_FAILED_OPEN = 4;

// I opted to do things with setutent/pututline etc manually instead of using the login/logout BSD functions due to
// running into some weird behaviour. Upon asking on IRC I was told to avoid these with a 10 foot pole and stick to this.

// The max byte length of the C string representing the TTY name.
static int max_len_tty_name() {
    return UT_LINESIZE;
}

// Low level C function to add a new USER_PROCESS entry to the database.
// This function does not perform any argument validation.
static int uacc_add_utmp_entry(const char *username, const char *hostname, const int32_t remote_addr_v6[4], const char *tty_name, const char *id, int32_t tv_sec, int32_t tv_usec) {
    struct utmp entry;
    entry.ut_type = USER_PROCESS;
    strncpy((char*) &entry.ut_line, tty_name, UT_LINESIZE);
    strncpy((char*) &entry.ut_id, id, sizeof(entry.ut_id));
    entry.ut_pid = getpid();
    strncpy((char*) &entry.ut_host, hostname, sizeof(entry.ut_host));
    strncpy((char*) &entry.ut_user, username, sizeof(entry.ut_user));
    entry.ut_session = 1;
    entry.ut_tv.tv_sec = tv_sec;
    entry.ut_tv.tv_usec = tv_usec;
    memcpy(&entry.ut_addr_v6, &remote_addr_v6, sizeof(int32_t) * 4);
    errno = 0;
    setutent();
    if (errno != 0) {
        return UACC_UTMP_FAILED_OPEN;
    }
    if (pututline(&entry) == NULL) {
        endutent();
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
    strncpy((char*) &line.ut_line, tty_name, UT_LINESIZE);
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
        endutent();
        return errno == EPERM || errno == EACCES ? UACC_UTMP_MISSING_PERMISSIONS : UACC_UTMP_WRITE_ERROR;
    }
    endutent();
    updwtmp(_PATH_WTMP, &entry);
    return 0;
}

#endif
