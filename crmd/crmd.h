/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRMD__H
#  define CRMD__H

#  define SYS_NAME     CRM_SYSTEM_CRMD
#  define PID_FILE     WORKING_DIR "/"SYS_NAME".pid"
#  define DAEMON_LOG   DEVEL_DIR"/"SYS_NAME".log"
#  define DAEMON_DEBUG DEVEL_DIR"/"SYS_NAME".debug"

extern GMainLoop *crmd_mainloop;
extern bool no_quorum_suicide_escalation;

void crmd_metadata(void);
void controld_election_init(const char *uname);
void controld_remove_voter(const char *uname);
void controld_stop_election_timeout(void);
void controld_election_fini(void);
void controld_set_election_period(const char *value);
void controld_stop_election_timer(void);

#endif
