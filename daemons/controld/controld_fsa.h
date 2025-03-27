/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRMD_FSA__H
#  define CRMD_FSA__H

#  include <crm/crm.h>
#  include <crm/cib.h>
#  include <crm/common/xml.h>
#  include <crm/common/mainloop.h>
#  include <crm/cluster.h>
#  include <crm/cluster/election_internal.h>
#  include <crm/common/ipc_internal.h>

/*! States the controller can be in */
enum crmd_fsa_state {
    S_IDLE = 0,                 /* Nothing happening */

    S_ELECTION,                 /* Take part in the election algorithm as
                                 * described below
                                 */
    S_INTEGRATION,              /* integrate that status of new nodes (which is
                                 * all of them if we have just been elected DC)
                                 * to form a complete and up-to-date picture of
                                 * the CIB
                                 */
    S_FINALIZE_JOIN,            /* integrate that status of new nodes (which is
                                 * all of them if we have just been elected DC)
                                 * to form a complete and up-to-date picture of
                                 * the CIB
                                 */
    S_NOT_DC,                   /* we are in non-DC mode */
    S_POLICY_ENGINE,            /* Determine next stable state of the cluster */
    S_RECOVERY,                 /* Something bad happened, check everything is ok
                                 * before continuing and attempt to recover if
                                 * required
                                 */
    S_RELEASE_DC,               /* we were the DC, but now we arent anymore,
                                 * possibly by our own request, and we should
                                 * release all unnecessary sub-systems, finish
                                 * any pending actions, do general cleanup and
                                 * unset anything that makes us think we are
                                 * special :)
                                 */
    S_STARTING,                 /* we are just starting out */
    S_PENDING,                  /* we are not a full/active member yet */
    S_STOPPING,                 /* We are in the final stages of shutting down */
    S_TERMINATE,                /* We are going to shutdown, this is the equiv of
                                 * "Sending TERM signal to all processes" in Linux
                                 * and in worst case scenarios could be considered
                                 * a self STONITH
                                 */
    S_TRANSITION_ENGINE,        /* Attempt to make the calculated next stable
                                 * state of the cluster a reality
                                 */

    S_HALT,                     /* Freeze - don't do anything
                                 * Something bad happened that needs the admin to fix
                                 * Wait for I_ELECTION
                                 */

    /*  ----------- Last input found in table is above ---------- */
    S_ILLEGAL                   /* This is an illegal FSA state */
        /* (must be last) */
};

#  define MAXSTATE S_ILLEGAL

/*
      Once we start and do some basic sanity checks, we go into the
      S_NOT_DC state and await instructions from the DC or input from
      the cluster layer which indicates the election algorithm needs to run.

      If the election algorithm is triggered, we enter the S_ELECTION state
      from where we can either go back to the S_NOT_DC state or progress
      to the S_INTEGRATION state (or S_RELEASE_DC if we used to be the DC
      but aren't anymore). See the libcrmcluster API documentation for more
      information about the election algorithm.

      Once the election is complete, if we are the DC, we enter the
      S_INTEGRATION state which is a DC-in-waiting style state.  We are
      the DC, but we shouldn't do anything yet because we may not have an
      up-to-date picture of the cluster.  There may of course be times
      when this fails, so we should go back to the S_RECOVERY stage and
      check everything is ok.  We may also end up here if a new node came
      online, since each node is authoritative about itself, and we would want
      to incorporate its information into the CIB.

      Once we have the latest CIB, we then enter the S_POLICY_ENGINE state
      where invoke the scheduler. It is possible that between
      invoking the scheduler and receiving an answer, that we receive
      more input. In this case, we would discard the orginal result and
      invoke it again.

      Once we are satisfied with the output from the scheduler, we
      enter S_TRANSITION_ENGINE and feed the scheduler's output to the
      Transition Engine who attempts to make the scheduler's
      calculation a reality. If the transition completes successfully,
      we enter S_IDLE, otherwise we go back to S_POLICY_ENGINE with the
      current unstable state and try again.

      Of course, we may be asked to shutdown at any time, however we must
      progress to S_NOT_DC before doing so.  Once we have handed over DC
      duties to another node, we can then shut down like everyone else,
      that is, by asking the DC for permission and waiting for it to take all
      our resources away.

      The case where we are the DC and the only node in the cluster is a
      special case and handled as an escalation which takes us to
      S_SHUTDOWN. Similarly, if any other point in the shutdown
      fails or stalls, this is escalated and we end up in S_TERMINATE.

      At any point, the controller can relay messages for its subsystems,
      but outbound messages (from subsystems) should probably be blocked
      until S_INTEGRATION (for the DC) or the join protocol has
      completed (for non-DC controllers).
*/

/*======================================
 *
 *  Inputs/Events/Stimuli to be given to the finite state machine
 *
 *  Some of these a true events, and others are synthesised based on
 *  the "register" (see below) and the contents or source of messages.
 *
 *  The machine keeps processing until receiving I_NULL
 *
 *======================================*/
enum crmd_fsa_input {
    I_NULL,                     /* Nothing happened */
    I_CIB_UPDATE,               /* An update to the CIB occurred */
    I_DC_TIMEOUT,               /* We have lost communication with the DC */
    I_ELECTION,                 /* Someone started an election */
    I_PE_CALC,                  /* The scheduler needs to be invoked */
    I_RELEASE_DC,               /* The election completed and we were not
                                 * elected, but we were the DC beforehand
                                 */
    I_ELECTION_DC,              /* The election completed and we were (re-)elected
                                 * DC
                                 */
    I_ERROR,                    /* Something bad happened (more serious than
                                 * I_FAIL) and may not have been due to the action
                                 * being performed.  For example, we may have lost
                                 * our connection to the CIB.
                                 */
    I_FAIL,                     /* The action failed to complete successfully */
    I_INTEGRATED,
    I_FINALIZED,
    I_NODE_JOIN,                /* A node has entered the cluster */
    I_NOT_DC,                   /* We are not and were not the DC before or after
                                 * the current operation or state
                                 */
    I_RECOVERED,                /* The recovery process completed successfully */
    I_RELEASE_FAIL,             /* We could not give up DC status for some reason
                                 */
    I_RELEASE_SUCCESS,          /* We are no longer the DC */
    I_RESTART,                  /* The current set of actions needs to be
                                 * restarted
                                 */
    I_TE_SUCCESS,               /* Some non-resource, non-cluster-layer action
                                 * is required of us, e.g. ping
                                 */
    I_ROUTER,                   /* Do our job as router and forward this to the
                                 * right place
                                 */
    I_SHUTDOWN,                 /* We are asking to shutdown */
    I_STOP,                     /* We have been told to shutdown */
    I_TERMINATE,                /* Actually exit */
    I_STARTUP,
    I_PE_SUCCESS,               /* The action completed successfully */
    I_JOIN_OFFER,               /* The DC is offering membership */
    I_JOIN_REQUEST,             /* The client is requesting membership */
    I_JOIN_RESULT,              /* If not the DC: The result of a join request
                                 * Else: A client is responding with its local state info
                                 */
    I_WAIT_FOR_EVENT,           /* we may be waiting for an async task to "happen"
                                 * and until it does, we can't do anything else
                                 */
    I_DC_HEARTBEAT,             /* The DC is telling us that it is alive and well */

    I_PENDING,
    I_HALT,

    /*  ------------ Last input found in table is above ----------- */
    I_ILLEGAL                   /* This is an illegal value for an FSA input */
        /* (must be last) */
};

#  define MAXINPUT  I_ILLEGAL

#  define I_MESSAGE I_ROUTER

/*======================================
 *
 * actions
 *
 * Some of the actions below will always occur together for now, but this may
 * not always be the case, so they are split up so that they can easily be
 * called independently in the future, if necessary.
 *
 * For example, separating A_LRM_CONNECT from A_STARTUP might be useful
 * if we ever try to recover from a faulty or disconnected executor.
 *
 *======================================*/

         /* Don't do anything */
#  define A_NOTHING                 0x0000000000000000ULL

/* -- Startup actions -- */
        /* Hook to perform any actions (other than connecting to other daemons)
         * that might be needed as part of the startup.
         */
#  define A_STARTUP                 0x0000000000000001ULL
        /* Hook to perform any actions that might be needed as part
         * after startup is successful.
         */
#  define A_STARTED                 0x0000000000000002ULL
        /* Connect to cluster layer */
#  define A_HA_CONNECT              0x0000000000000004ULL
#  define A_HA_DISCONNECT           0x0000000000000008ULL

#  define A_INTEGRATE_TIMER_START   0x0000000000000010ULL
#  define A_INTEGRATE_TIMER_STOP    0x0000000000000020ULL
#  define A_FINALIZE_TIMER_START    0x0000000000000040ULL
#  define A_FINALIZE_TIMER_STOP     0x0000000000000080ULL

/* -- Election actions -- */
#  define A_DC_TIMER_START          0x0000000000000100ULL
#  define A_DC_TIMER_STOP           0x0000000000000200ULL
#  define A_ELECTION_COUNT          0x0000000000000400ULL
#  define A_ELECTION_VOTE           0x0000000000000800ULL

#  define A_ELECTION_START          0x0000000000001000ULL

/* -- Message processing -- */
        /* Process the queue of requests */
#  define A_MSG_PROCESS             0x0000000000002000ULL
        /* Send the message to the correct recipient */
#  define A_MSG_ROUTE               0x0000000000004000ULL

        /* Send a welcome message to new node(s) */
#  define A_DC_JOIN_OFFER_ONE       0x0000000000008000ULL

/* -- Server Join protocol actions -- */
        /* Send a welcome message to all nodes */
#  define A_DC_JOIN_OFFER_ALL       0x0000000000010000ULL
        /* Process the remote node's ack of our join message */
#  define A_DC_JOIN_PROCESS_REQ     0x0000000000020000ULL
        /* Send out the results of the Join phase */
#  define A_DC_JOIN_FINALIZE        0x0000000000040000ULL
        /* Send out the results of the Join phase */
#  define A_DC_JOIN_PROCESS_ACK     0x0000000000080000ULL

/* -- Client Join protocol actions -- */
#  define A_CL_JOIN_QUERY           0x0000000000100000ULL
#  define A_CL_JOIN_ANNOUNCE        0x0000000000200000ULL
        /* Request membership to the DC list */
#  define A_CL_JOIN_REQUEST         0x0000000000400000ULL
        /* Did the DC accept or reject the request */
#  define A_CL_JOIN_RESULT          0x0000000000800000ULL

/* -- Recovery, DC start/stop -- */
        /* Something bad happened, try to recover */
#  define A_RECOVER                 0x0000000001000000ULL
        /* Hook to perform any actions (apart from starting, the TE, scheduler,
         * and gathering the latest CIB) that might be necessary before
         * giving up the responsibilities of being the DC.
         */
#  define A_DC_RELEASE              0x0000000002000000ULL
        /* */
#  define A_DC_RELEASED             0x0000000004000000ULL
        /* Hook to perform any actions (apart from starting, the TE, scheduler,
         * and gathering the latest CIB) that might be necessary before
         * taking over the responsibilities of being the DC.
         */
#  define A_DC_TAKEOVER             0x0000000008000000ULL

/* -- Shutdown actions -- */
#  define A_SHUTDOWN                0x0000000010000000ULL
#  define A_STOP                    0x0000000020000000ULL
#  define A_EXIT_0                  0x0000000040000000ULL
#  define A_EXIT_1                  0x0000000080000000ULL

#  define A_SHUTDOWN_REQ            0x0000000100000000ULL
#  define A_ELECTION_CHECK          0x0000000200000000ULL
#  define A_DC_JOIN_FINAL           0x0000000400000000ULL

/* -- CIB actions -- */
#  define A_CIB_START               0x0000020000000000ULL
#  define A_CIB_STOP                0x0000040000000000ULL

/* -- Transition Engine actions -- */
        /* Attempt to reach the newly calculated cluster state. This is
         * only called once per transition (except if it is asked to
         * stop the transition or start a new one).
         * Once given a cluster state to reach, the TE will determine
         * tasks that can be performed in parallel, execute them, wait
         * for replies and then determine the next set until the new
         * state is reached or no further tasks can be taken.
         */
#  define A_TE_INVOKE               0x0000100000000000ULL
#  define A_TE_START                0x0000200000000000ULL
#  define A_TE_STOP                 0x0000400000000000ULL
#  define A_TE_CANCEL               0x0000800000000000ULL
#  define A_TE_HALT                 0x0001000000000000ULL

/* -- Scheduler actions -- */
        /* Calculate the next state for the cluster.  This is only
         * invoked once per needed calculation.
         */
#  define A_PE_INVOKE               0x0002000000000000ULL
#  define A_PE_START                0x0004000000000000ULL
#  define A_PE_STOP                 0x0008000000000000ULL
/* -- Misc actions -- */
        /* Add a system generate "block" so that resources arent moved
         * to or are activly moved away from the affected node.  This
         * way we can return quickly even if busy with other things.
         */
#  define A_NODE_BLOCK              0x0010000000000000ULL
        /* Update our information in the local CIB */
#  define A_UPDATE_NODESTATUS       0x0020000000000000ULL
#  define A_READCONFIG              0x0080000000000000ULL

/* -- LRM Actions -- */
        // Connect to the local executor
#  define A_LRM_CONNECT             0x0100000000000000ULL
        // Disconnect from the local executor
#  define A_LRM_DISCONNECT          0x0200000000000000ULL
#  define A_LRM_INVOKE              0x0400000000000000ULL

/* -- Logging actions -- */
#  define A_LOG                     0x1000000000000000ULL
#  define A_ERROR                   0x2000000000000000ULL
#  define A_WARN                    0x4000000000000000ULL

#  define O_EXIT                (A_SHUTDOWN|A_STOP|A_LRM_DISCONNECT|A_HA_DISCONNECT|A_EXIT_0|A_CIB_STOP)
#  define O_RELEASE             (A_DC_TIMER_STOP|A_DC_RELEASE|A_PE_STOP|A_TE_STOP|A_DC_RELEASED)
#  define O_PE_RESTART          (A_PE_START|A_PE_STOP)
#  define O_TE_RESTART          (A_TE_START|A_TE_STOP)
#  define O_CIB_RESTART         (A_CIB_START|A_CIB_STOP)
#  define O_LRM_RECONNECT       (A_LRM_CONNECT|A_LRM_DISCONNECT)
#  define O_DC_TIMER_RESTART    (A_DC_TIMER_STOP|A_DC_TIMER_START)
/*======================================
 *
 * "register" contents
 *
 * Things we may want to remember regardless of which state we are in.
 *
 * These also count as inputs for synthesizing I_*
 *
 *======================================*/
#  define R_THE_DC          0x00000001ULL
                                        /* Are we the DC? */
#  define R_STARTING        0x00000002ULL
                                        /* Are we starting up? */
#  define R_SHUTDOWN        0x00000004ULL
                                        /* Are we trying to shut down? */
#  define R_STAYDOWN        0x00000008ULL
                                        /* Should we restart? */

#  define R_JOIN_OK         0x00000010ULL   /* Have we completed the join process */
#  define R_READ_CONFIG     0x00000040ULL
#  define R_INVOKE_PE       0x00000080ULL   // Should the scheduler be invoked?

#  define R_CIB_CONNECTED   0x00000100ULL
                                        /* Is the CIB connected? */
#  define R_PE_CONNECTED    0x00000200ULL   // Is the scheduler connected?
#  define R_TE_CONNECTED    0x00000400ULL
                                        /* Is the Transition Engine connected? */
#  define R_LRM_CONNECTED   0x00000800ULL   // Is the executor connected?

#  define R_CIB_REQUIRED    0x00001000ULL
                                        /* Is the CIB required? */
#  define R_PE_REQUIRED     0x00002000ULL   // Is the scheduler required?
#  define R_TE_REQUIRED     0x00004000ULL
                                        /* Is the Transition Engine required? */
#  define R_ST_REQUIRED     0x00008000ULL
                                        /* Is the Stonith daemon required? */

#  define R_CIB_DONE        0x00010000ULL
                                        /* Have we calculated the CIB? */
#  define R_HAVE_CIB        0x00020000ULL   /* Do we have an up-to-date CIB */

#  define R_MEMBERSHIP      0x00100000ULL   /* Have we got cluster layer data yet */

// Ever received membership-layer data
#  define R_PEER_DATA       0x00200000ULL

#  define R_HA_DISCONNECTED 0x00400000ULL      /* did we sign out of our own accord */

#  define R_REQ_PEND        0x01000000ULL
                                        /* Are there Requests waiting for
                                           processing? */
#  define R_PE_PEND         0x02000000ULL   // Are we awaiting reply from scheduler?
#  define R_TE_PEND         0x04000000ULL
                                        /* Has the TE been invoked and we're
                                           awaiting completion? */
#  define R_RESP_PEND       0x08000000ULL
                                        /* Do we have clients waiting on a
                                           response? if so perhaps we shouldn't
                                           stop yet */

#  define R_SENT_RSC_STOP   0x20000000ULL /* Have we sent a stop action to all
                                         * resources in preparation for
                                         * shutting down */

#  define R_IN_RECOVERY     0x80000000ULL

#define CRM_DIRECT_NACK_RC (99) // Deprecated (see PCMK_EXEC_INVALID)

enum crmd_fsa_cause {
    C_UNKNOWN = 0,
    C_STARTUP,
    C_IPC_MESSAGE,
    C_HA_MESSAGE,
    C_CRMD_STATUS_CALLBACK,
    C_LRM_OP_CALLBACK,
    C_TIMER_POPPED,
    C_SHUTDOWN,
    C_FSA_INTERNAL,
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
    uint64_t actions;
    const char *origin;
    void *data;
    enum fsa_data_type data_type;
};

#define controld_set_fsa_input_flags(flags_to_set) do {                 \
        controld_globals.fsa_input_register                             \
            = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,         \
                                 "FSA input", "controller",             \
                                 controld_globals.fsa_input_register,   \
                                 (flags_to_set), #flags_to_set);        \
    } while (0)

#define controld_clear_fsa_input_flags(flags_to_clear) do {             \
        controld_globals.fsa_input_register                             \
            = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,       \
                                   "FSA input", "controller",           \
                                   controld_globals.fsa_input_register, \
                                   (flags_to_clear),                    \
                                   #flags_to_clear);                    \
    } while (0)

#define controld_set_fsa_action_flags(flags_to_set) do {            \
        controld_globals.fsa_actions                                \
            = pcmk__set_flags_as(__func__, __LINE__, LOG_DEBUG,     \
                                 "FSA action", "controller",        \
                                 controld_globals.fsa_actions,      \
                                 (flags_to_set), #flags_to_set);    \
    } while (0)

#define controld_clear_fsa_action_flags(flags_to_clear) do {            \
        controld_globals.fsa_actions                                    \
            = pcmk__clear_flags_as(__func__, __LINE__, LOG_DEBUG,       \
                                   "FSA action", "controller",          \
                                   controld_globals.fsa_actions,        \
                                   (flags_to_clear), #flags_to_clear);  \
    } while (0)

// This should be moved elsewhere
xmlNode *controld_query_executor_state(void);

const char *fsa_input2string(enum crmd_fsa_input input);
const char *fsa_state2string(enum crmd_fsa_state state);
const char *fsa_cause2string(enum crmd_fsa_cause cause);
const char *fsa_action2string(long long action);

enum crmd_fsa_state s_crmd_fsa(enum crmd_fsa_cause cause);

enum crmd_fsa_state controld_fsa_get_next_state(enum crmd_fsa_input input);

uint64_t controld_fsa_get_action(enum crmd_fsa_input input);

void controld_init_fsa_trigger(void);
void controld_destroy_fsa_trigger(void);

void free_max_generation(void);

#define AM_I_DC pcmk__is_set(controld_globals.fsa_input_register, R_THE_DC)
#define controld_trigger_fsa() controld_trigger_fsa_as(__func__, __LINE__)

void controld_trigger_fsa_as(const char *fn, int line);

/* A_READCONFIG */
void do_read_config(long long action, enum crmd_fsa_cause cause,
                    enum crmd_fsa_state cur_state,
                    enum crmd_fsa_input current_input, fsa_data_t *msg_data);

/* A_PE_INVOKE */
void do_pe_invoke(long long action, enum crmd_fsa_cause cause,
                  enum crmd_fsa_state cur_state,
                  enum crmd_fsa_input current_input, fsa_data_t *msg_data);

/* A_LOG */
void do_log(long long action, enum crmd_fsa_cause cause,
            enum crmd_fsa_state cur_state,
            enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_STARTUP */
void do_startup(long long action, enum crmd_fsa_cause cause,
                enum crmd_fsa_state cur_state,
                enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_CIB_START, STOP, RESTART */
void do_cib_control(long long action, enum crmd_fsa_cause cause,
                    enum crmd_fsa_state cur_state,
                    enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_HA_CONNECT */
void do_ha_control(long long action, enum crmd_fsa_cause cause,
                   enum crmd_fsa_state cur_state,
                   enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_LRM_CONNECT */
void do_lrm_control(long long action, enum crmd_fsa_cause cause,
                    enum crmd_fsa_state cur_state,
                    enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_PE_START, STOP, RESTART */
void do_pe_control(long long action, enum crmd_fsa_cause cause,
                   enum crmd_fsa_state cur_state,
                   enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_TE_START, STOP, RESTART */
void do_te_control(long long action, enum crmd_fsa_cause cause,
                   enum crmd_fsa_state cur_state,
                   enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_STARTED */
void do_started(long long action, enum crmd_fsa_cause cause,
                enum crmd_fsa_state cur_state,
                enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_MSG_ROUTE */
void do_msg_route(long long action, enum crmd_fsa_cause cause,
                  enum crmd_fsa_state cur_state,
                  enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_RECOVER */
void do_recover(long long action, enum crmd_fsa_cause cause,
                enum crmd_fsa_state cur_state,
                enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_ELECTION_VOTE */
void do_election_vote(long long action, enum crmd_fsa_cause cause,
                      enum crmd_fsa_state cur_state,
                      enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_ELECTION_COUNT */
void do_election_count_vote(long long action, enum crmd_fsa_cause cause,
                            enum crmd_fsa_state cur_state,
                            enum crmd_fsa_input cur_input,
                            fsa_data_t *msg_data);

/* A_ELECTION_CHECK */
void do_election_check(long long action, enum crmd_fsa_cause cause,
                       enum crmd_fsa_state cur_state,
                       enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_DC_TIMER_STOP */
void do_timer_control(long long action, enum crmd_fsa_cause cause,
                      enum crmd_fsa_state cur_state,
                      enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_DC_TAKEOVER */
void do_dc_takeover(long long action, enum crmd_fsa_cause cause,
                    enum crmd_fsa_state cur_state,
                    enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_DC_RELEASE */
void do_dc_release(long long action, enum crmd_fsa_cause cause,
                   enum crmd_fsa_state cur_state,
                   enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_DC_JOIN_OFFER_ALL */
void do_dc_join_offer_all(long long action, enum crmd_fsa_cause cause,
                          enum crmd_fsa_state cur_state,
                          enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_DC_JOIN_OFFER_ONE */
void do_dc_join_offer_one(long long action, enum crmd_fsa_cause cause,
                          enum crmd_fsa_state cur_state,
                          enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_DC_JOIN_ACK */
void do_dc_join_ack(long long action, enum crmd_fsa_cause cause,
                    enum crmd_fsa_state cur_state,
                    enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_DC_JOIN_REQ */
void do_dc_join_filter_offer(long long action, enum crmd_fsa_cause cause,
                             enum crmd_fsa_state cur_state,
                             enum crmd_fsa_input cur_input,
                             fsa_data_t *msg_data);

/* A_DC_JOIN_FINALIZE */
void do_dc_join_finalize(long long action, enum crmd_fsa_cause cause,
                         enum crmd_fsa_state cur_state,
                         enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_CL_JOIN_QUERY */
/* is there a DC out there? */
void do_cl_join_query(long long action, enum crmd_fsa_cause cause,
                      enum crmd_fsa_state cur_state,
                      enum crmd_fsa_input current_input, fsa_data_t *msg_data);

/* A_CL_JOIN_ANNOUNCE */
void do_cl_join_announce(long long action, enum crmd_fsa_cause cause,
                         enum crmd_fsa_state cur_state,
                         enum crmd_fsa_input current_input, fsa_data_t *msg_data);

/* A_CL_JOIN_REQUEST */
void do_cl_join_offer_respond(long long action, enum crmd_fsa_cause cause,
                              enum crmd_fsa_state cur_state,
                              enum crmd_fsa_input current_input,
                              fsa_data_t *msg_data);

/* A_CL_JOIN_RESULT */
void do_cl_join_finalize_respond(long long action, enum crmd_fsa_cause cause,
                                 enum crmd_fsa_state cur_state,
                                 enum crmd_fsa_input current_input,
                                 fsa_data_t *msg_data);

/* A_LRM_INVOKE */
void do_lrm_invoke(long long action, enum crmd_fsa_cause cause,
                   enum crmd_fsa_state cur_state,
                   enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_TE_INVOKE, A_TE_CANCEL */
void do_te_invoke(long long action, enum crmd_fsa_cause cause,
                  enum crmd_fsa_state cur_state,
                  enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_SHUTDOWN_REQ */
void do_shutdown_req(long long action, enum crmd_fsa_cause cause,
                     enum crmd_fsa_state cur_state,
                     enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_SHUTDOWN */
void do_shutdown(long long action, enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_STOP */
void do_stop(long long action, enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state,
             enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_EXIT_0, A_EXIT_1 */
void do_exit(long long action, enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state,
             enum crmd_fsa_input cur_input, fsa_data_t *msg_data);

/* A_DC_JOIN_FINAL */
void do_dc_join_final(long long action, enum crmd_fsa_cause cause,
                      enum crmd_fsa_state cur_state,
                      enum crmd_fsa_input current_input, fsa_data_t *msg_data);
#endif
