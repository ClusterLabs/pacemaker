/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__IPC_INTERNAL_H
#define PCMK__IPC_INTERNAL_H

#include <sys/types.h>

#include <crm_config.h>  /* US_AUTH_GETPEEREID */


/* denotes "non yieldable PID" on FreeBSD, or actual PID1 in scenarios that
   require a delicate handling anyway (socket-based activation with systemd);
   we can be reasonably sure that this PID is never possessed by the actual
   child daemon, as it gets taken either by the proper init, or by pacemakerd
   itself (i.e. this precludes anything else); note that value of zero
   is meant to carry "unset" meaning, and better not to bet on/conditionalize
   over signedness of pid_t */
#define PCMK__SPECIAL_PID  1

#if defined(US_AUTH_GETPEEREID)
/* on FreeBSD, we don't want to expose "non-yieldable PID" (leading to
   "IPC liveness check only") as its nominal representation, which could
   cause confusion -- this is unambiguous as long as there's no
   socket-based activation like with systemd (very improbable) */
#define PCMK__SPECIAL_PID_AS_0(p)  (((p) == PCMK__SPECIAL_PID) ? 0 : (p))
#else
#define PCMK__SPECIAL_PID_AS_0(p)  (p)
#endif

/*!
 * \internal
 * \brief Check the authenticity and liveness of the process via IPC end-point
 *
 * When IPC daemon under given IPC end-point (name) detected, its authenticity
 * is verified by the means of comparing against provided referential UID and
 * GID, and the result of this check can be deduced from the return value.
 * As an exception, referential UID of 0 (~ root) satisfies arbitrary
 * detected daemon's credentials.
 *
 * \param[in]  name    IPC name to base the search on
 * \param[in]  refuid  referential UID to check against
 * \param[in]  refgid  referential GID to check against
 * \param[out] gotpid  to optionally store obtained PID of the found process
 *                     upon returning 1 or -2
 *                     (not available on FreeBSD, special value of 1,
 *                     see PCMK__SPECIAL_PID, used instead, and the caller
 *                     is required to special case this value respectively)
 *
 * \return 0 if no trace of IPC peer's liveness detected, 1 if it was,
 *         -1 on error, and -2 when the IPC blocked with unauthorized
 *         process (log message emitted in both latter cases)
 *
 * \note This function emits a log message also in case there isn't a perfect
 *       match in respect to \p reguid and/or \p refgid, for a possible
 *       least privilege principle violation.
 *
 * \see crm_ipc_is_authentic_process
 */
int pcmk__ipc_is_authentic_process_active(const char *name, uid_t refuid,
                                          gid_t refgid, pid_t *gotpid);

#endif
