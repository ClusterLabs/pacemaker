/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRMD_FSA__H
#  define CRMD_FSA__H

#  include <fsa_defines.h>

#  include <crm/crm.h>
#  include <crm/cib.h>
#  include <crm/common/xml.h>
#  include <crm/common/mainloop.h>
#  include <crm/cluster.h>
#  include <crm/common/ipcs.h>

#  if SUPPORT_HEARTBEAT
extern ll_cluster_t *fsa_cluster_conn;
#  endif

/* copy from struct client_child in heartbeat.h
 *
 * Plus a couple of other things
 */
struct crm_subsystem_s {
    pid_t pid;                  /* Process id of child process */
    const char *name;           /* executable name */
    const char *path;           /* Command location */
    const char *command;        /* Command with path */
    const char *args;           /* Command arguments */
    crm_client_t *client;       /* Client connection object */

    gboolean sent_kill;
    mainloop_io_t *source;      /* How can we communicate with it */
    long long flag_connected;   /*  */
    long long flag_required;    /*  */
};

typedef struct fsa_timer_s fsa_timer_t;
struct fsa_timer_s {
    guint source_id;            /* timer source id */
    int period_ms;              /* timer period */
    enum crmd_fsa_input fsa_input;
     gboolean(*callback) (gpointer data);
    gboolean repeat;
    int counter;
};

enum fsa_data_type {
    fsa_dt_none,
    fsa_dt_ha_msg,
    fsa_dt_xml,
    fsa_dt_lrm,
};

typedef struct fsa_data_s fsa_data_t;
struct fsa_data_s {
    int id;
    enum crmd_fsa_input fsa_input;
    enum crmd_fsa_cause fsa_cause;
    long long actions;
    const char *origin;
    void *data;
    enum fsa_data_type data_type;
};

extern enum crmd_fsa_state s_crmd_fsa(enum crmd_fsa_cause cause);

/* Global FSA stuff */
extern volatile gboolean do_fsa_stall;
extern volatile enum crmd_fsa_state fsa_state;
extern volatile long long fsa_input_register;
extern volatile long long fsa_actions;

extern cib_t *fsa_cib_conn;

extern char *fsa_our_uname;
extern char *fsa_our_uuid;
extern char *fsa_pe_ref;        /* the last invocation of the PE */
extern char *fsa_our_dc;
extern char *fsa_our_dc_version;
extern GListPtr fsa_message_queue;

extern fsa_timer_t *election_trigger;   /*  */
extern fsa_timer_t *election_timeout;   /*  */
extern fsa_timer_t *shutdown_escalation_timer;  /*  */
extern fsa_timer_t *transition_timer;
extern fsa_timer_t *integration_timer;
extern fsa_timer_t *finalization_timer;
extern fsa_timer_t *wait_timer;
extern fsa_timer_t *recheck_timer;

extern crm_trigger_t *fsa_source;
extern crm_trigger_t *config_read;

extern struct crm_subsystem_s *cib_subsystem;
extern struct crm_subsystem_s *te_subsystem;
extern struct crm_subsystem_s *pe_subsystem;

/* these two should be moved elsewhere... */
extern void do_update_cib_nodes(gboolean overwrite, const char *caller);
extern gboolean do_dc_heartbeat(gpointer data);

#  define AM_I_DC is_set(fsa_input_register, R_THE_DC)
#  define AM_I_OPERATIONAL (is_set(fsa_input_register, R_STARTING)==FALSE)
extern unsigned long long saved_ccm_membership_id;
extern gboolean ever_had_quorum;

#  include <fsa_proto.h>
#  include <crmd_utils.h>

#  define trigger_fsa(source) crm_trace("Triggering FSA: %s", __FUNCTION__); \
	mainloop_set_trigger(source);

#endif
