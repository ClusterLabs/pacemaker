/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_IO_INTERNAL__H
#  define PCMK__CRM_COMMON_IO_INTERNAL__H

#include <fcntl.h>              // open()
#include <stdbool.h>            // bool
#include <unistd.h>             // uid_t, gid_t

int pcmk__real_path(const char *path, char **resolved_path);

char *pcmk__series_filename(const char *directory, const char *series,
                            int sequence, bool bzip);
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

void pcmk__close_fds_in_child(bool);

/*!
 * \internal
 * \brief Open /dev/null to consume next available file descriptor
 *
 * Open /dev/null, disregarding the result. This is intended when daemonizing to
 * be able to null stdin, stdout, and stderr.
 *
 * \param[in] flags  O_RDONLY (stdin) or O_WRONLY (stdout and stderr)
 */
static inline void
pcmk__open_devnull(int flags)
{
    // Static analysis clutter
    // cppcheck-suppress leakReturnValNotUsed
    (void) open("/dev/null", flags);
}

#endif // PCMK__CRM_COMMON_IO_INTERNAL__H
