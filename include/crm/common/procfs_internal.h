/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_PROCFS_INTERNAL__H
#define PCMK__CRM_COMMON_PROCFS_INTERNAL__H

#include <dirent.h>             // DIR
#include <stdbool.h>            // bool
#include <sys/types.h>          // pid_t

#ifdef __cplusplus
extern "C" {
#endif

pid_t pcmk__procfs_pid_of(const char *name);
unsigned int pcmk__procfs_num_cores(void);
int pcmk__procfs_pid2path(pid_t pid, char **path);
bool pcmk__procfs_has_pids(void);
DIR *pcmk__procfs_fd_dir(void);
void pcmk__sysrq_trigger(char t);
bool pcmk__throttle_cib_load(const char *server, float *load);
bool pcmk__throttle_load_avg(float *load);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_PROCFS_INTERNAL__H
