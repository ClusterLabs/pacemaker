/*
 * Copyright 2021-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__COMMON_MOCK_PRIVATE__H
#define PCMK__COMMON_MOCK_PRIVATE__H

#include <pwd.h>                    // struct passwd
#include <stdbool.h>                // bool
#include <stdio.h>                  // FILE
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>              // pid_t, size_t
#include <sys/utsname.h>
#include <unistd.h>
#include <grp.h>                    // struct group

#include <crm/common/results.h>     // _Noreturn

#ifdef __cplusplus
extern "C" {

// C++ doesn't support the restrict keyword
#define restrict
#endif

/* This header is for the sole use of libcrmcommon_test and unit tests */

_Noreturn void __real_abort(void);
_Noreturn void __wrap_abort(void);

extern bool pcmk__mock_calloc;
void *__real_calloc(size_t nmemb, size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);

extern bool pcmk__mock_fopen;
FILE *__real_fopen(const char *pathname, const char *mode);
FILE *__wrap_fopen(const char *pathname, const char *mode);
#ifdef HAVE_FOPEN64
FILE *__real_fopen64(const char *pathname, const char *mode);
FILE *__wrap_fopen64(const char *pathname, const char *mode);
#endif

extern bool pcmk__mock_getenv;
char *__real_getenv(const char *name);
char *__wrap_getenv(const char *name);

extern bool pcmk__mock_realloc;
void *__real_realloc(void *ptr, size_t size);
void *__wrap_realloc(void *ptr, size_t size);

extern bool pcmk__mock_setenv;
int __real_setenv(const char *name, const char *value, int overwrite);
int __wrap_setenv(const char *name, const char *value, int overwrite);

extern bool pcmk__mock_unsetenv;
int __real_unsetenv(const char *name);
int __wrap_unsetenv(const char *name);

extern bool pcmk__mock_getpid;
pid_t __real_getpid(void);
pid_t __wrap_getpid(void);

extern bool pcmk__mock_getpwnam;
struct passwd *__real_getpwnam(const char *name);
struct passwd *__wrap_getpwnam(const char *name);

extern bool pcmk__mock_getgrnam;
struct group *__real_getgrnam(const char *name);
struct group *__wrap_getgrnam(const char *name);

extern bool pcmk__mock_readlink;
ssize_t __real_readlink(const char *restrict path, char *restrict buf,
                        size_t bufsize);
ssize_t __wrap_readlink(const char *restrict path, char *restrict buf,
                        size_t bufsize);

extern bool pcmk__mock_strdup;
char *__real_strdup(const char *s);
char *__wrap_strdup(const char *s);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__COMMON_MOCK_PRIVATE__H
