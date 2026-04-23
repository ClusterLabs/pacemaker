/*
 * Copyright 2022-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <io_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_IO_INTERNAL__H
#define PCMK__CRM_COMMON_IO_INTERNAL__H

#include <fcntl.h>              // open()
#include <stdbool.h>            // bool
#include <stdio.h>              // freopen()
#include <unistd.h>             // uid_t, gid_t

#ifdef __cplusplus
extern "C" {
#endif

/* Define compression parameters for IPC messages
 *
 * Compression costs a LOT, so we don't want to do it unless we're hitting
 * message limits. Currently, we use 128KB as the threshold, because higher
 * values don't play well with the heartbeat stack. With an earlier limit of
 * 10KB, compressing 184 of 1071 messages accounted for 23% of the total CPU
 * used by the cib.
 */
#define PCMK__BZ2_BLOCKS    4
#define PCMK__BZ2_WORK      20
#define PCMK__BZ2_THRESHOLD (128 * 1024)

int pcmk__real_path(const char *path, char **resolved_path);

char *pcmk__series_filename(const char *directory, const char *series,
                            unsigned int sequence, bool bzip);
int pcmk__read_series_sequence(const char *directory, const char *series,
                               unsigned int *seq);
void pcmk__write_series_sequence(const char *directory, const char *series,
                                 unsigned int sequence, int max);
int pcmk__chown_series_sequence(const char *directory, const char *series,
                                uid_t uid, gid_t gid);

int pcmk__build_path(const char *path_c, mode_t mode);
char *pcmk__full_path(const char *filename, const char *dirname);
bool pcmk__daemon_can_write(const char *dir, const char *file);
void pcmk__sync_directory(const char *name);

int pcmk__file_contents(const char *filename, char **contents);
int pcmk__write_sync(int fd, const char *contents);
int pcmk__set_nonblocking(int fd);
const char *pcmk__get_tmpdir(void);

void pcmk__close_fds_in_child(void);

/*!
 * \internal
 * \brief Reopen the standard streams using \c /dev/null
 *
 * This is intended for use when daemonizing, to null \c stdin, \c stdout,
 * and \c stderr. Failures are ignored.
 */
static inline void
pcmk__null_std_streams(void)
{
    /* The "(void) !" is to suppress an obnoxious gcc warning. At least on some
     * systems, freopen() has the attribute __warn_unused_result__. "(void)"
     * alone does not suppress the warning. This policy is controversial but
     * intentional and longstanding.
     *
     * https://stackoverflow.com/questions/40576003/ignoring-warning-wunused-result
     * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425#c34
     *
     * @TODO Consider replacing our uses of fork() with g_subprocess_*() or
     * g_spawn_*(). These interfaces have arguments for redirecting standard
     * streams to /dev/null.
     */
    (void) !freopen("/dev/null", "r", stdin);
    (void) !freopen("/dev/null", "w", stdout);
    (void) !freopen("/dev/null", "w", stderr);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_IO_INTERNAL__H
