/*
 * Copyright 2021-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef MOCK_PRIVATE__H
#  define MOCK_PRIVATE__H

#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <grp.h>

/* This header is for the sole use of libcrmcommon_test and unit tests */

extern bool pcmk__mock_calloc;
void *__real_calloc(size_t nmemb, size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);

extern bool pcmk__mock_getenv;
char *__real_getenv(const char *name);
char *__wrap_getenv(const char *name);

extern bool pcmk__mock_getpid;
pid_t __real_getpid(void);
pid_t __wrap_getpid(void);

extern bool pcmk__mock_grent;
void __real_setgrent(void);
void __wrap_setgrent(void);
struct group * __wrap_getgrent(void);
struct group * __real_getgrent(void);
void __wrap_endgrent(void);
void __real_endgrent(void);

extern bool pcmk__mock_getpwnam_r;
int __real_getpwnam_r(const char *name, struct passwd *pwd,
                      char *buf, size_t buflen, struct passwd **result);
int __wrap_getpwnam_r(const char *name, struct passwd *pwd,
                      char *buf, size_t buflen, struct passwd **result);

extern bool pcmk__mock_readlink;
ssize_t __real_readlink(const char *restrict path, char *restrict buf,
                        size_t bufsize);
ssize_t __wrap_readlink(const char *restrict path, char *restrict buf,
                        size_t bufsize);

extern bool pcmk__mock_strdup;
char *__real_strdup(const char *s);
char *__wrap_strdup(const char *s);

extern bool pcmk__mock_uname;
int __real_uname(struct utsname *buf);
int __wrap_uname(struct utsname *buf);

#endif  // MOCK_PRIVATE__H
