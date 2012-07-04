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

#include <crm_internal.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <crmd_fsa.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>             /* for access */

#include <sys/types.h>          /* for calls to open */
#include <sys/stat.h>           /* for calls to open */
#include <fcntl.h>              /* for calls to open */
#include <pwd.h>                /* for getpwuid */
#include <grp.h>                /* for initgroups */

#include <sys/time.h>           /* for getrlimit */
#include <sys/resource.h>       /* for getrlimit */

#include <errno.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/cib.h>
#include <crmd.h>

#include <tengine.h>

struct crm_subsystem_s *cib_subsystem = NULL;

int cib_retries = 0;

static void
do_cib_updated(const char *event, xmlNode * msg)
{
    int rc = -1;

    CRM_CHECK(msg != NULL, return);
    crm_element_value_int(msg, F_CIB_RC, &rc);
    if (rc < pcmk_ok) {
        crm_trace("Filter rc=%d (%s)", rc, pcmk_strerror(rc));
        return;
    }

    if (get_xpath_object
        ("//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_CIB_TAG_CRMCONFIG, msg,
         LOG_TRACE) != NULL) {
        mainloop_set_trigger(config_read);
    }
}

static void
revision_check_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    int cmp = -1;
    const char *revision = NULL;
    xmlNode *generation = NULL;

    if (rc != pcmk_ok) {
        fsa_data_t *msg_data = NULL;

        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
        return;
    }

    generation = output;
    CRM_CHECK(safe_str_eq(crm_element_name(generation), XML_TAG_CIB),
              crm_log_xml_err(output, __FUNCTION__); return);

    crm_trace("Checking our feature revision is allowed: %s", CIB_FEATURE_SET);

    revision = crm_element_value(generation, XML_ATTR_CRM_VERSION);
    cmp = compare_version(revision, CRM_FEATURE_SET);

    if (cmp > 0) {
        crm_err("This build (%s) does not support the current" " resource configuration", VERSION);
        crm_err("We can only support up to CRM feature set %s (current=%s)",
                CRM_FEATURE_SET, revision);
        crm_err("Shutting down the CRM");
        /* go into a stall state */
        register_fsa_error_adv(C_FSA_INTERNAL, I_SHUTDOWN, NULL, NULL, __FUNCTION__);
        return;
    }
}

static void
do_cib_replaced(const char *event, xmlNode * msg)
{
    crm_debug("Updating the CIB after a replace: DC=%s", AM_I_DC ? "true" : "false");
    if (AM_I_DC == FALSE) {
        return;

    } else if (fsa_state == S_FINALIZE_JOIN && is_set(fsa_input_register, R_CIB_ASKED)) {
        /* no need to restart the join - we asked for this replace op */
        return;
    }

    /* start the join process again so we get everyone's LRM status */
    populate_cib_nodes(FALSE);
    do_update_cib_nodes(TRUE, __FUNCTION__);
    register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);
}

/*	 A_CIB_STOP, A_CIB_START, A_CIB_RESTART,	*/
void
do_cib_control(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    struct crm_subsystem_s *this_subsys = cib_subsystem;

    long long stop_actions = A_CIB_STOP;
    long long start_actions = A_CIB_START;

    if (action & stop_actions) {
        crm_info("Disconnecting CIB");
        clear_bit(fsa_input_register, R_CIB_CONNECTED);
        CRM_ASSERT(fsa_cib_conn != NULL);

        fsa_cib_conn->cmds->del_notify_callback(fsa_cib_conn, T_CIB_DIFF_NOTIFY, do_cib_updated);

        if (fsa_cib_conn->state != cib_disconnected) {
            fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);
            fsa_cib_conn->cmds->signoff(fsa_cib_conn);
        }
    }

    if (action & start_actions) {
        int rc = pcmk_ok;

        CRM_ASSERT(fsa_cib_conn != NULL);

        if (cur_state == S_STOPPING) {
            crm_err("Ignoring request to start %s after shutdown", this_subsys->name);
            return;
        }

        rc = fsa_cib_conn->cmds->signon(fsa_cib_conn, CRM_SYSTEM_CRMD, cib_command_nonblocking);

        if (rc != pcmk_ok) {
            /* a short wait that usually avoids stalling the FSA */
            sleep(1);
            rc = fsa_cib_conn->cmds->signon(fsa_cib_conn, CRM_SYSTEM_CRMD, cib_command_nonblocking);
        }

        if (rc != pcmk_ok) {
            crm_info("Could not connect to the CIB service: %s", pcmk_strerror(rc));

        } else if (pcmk_ok !=
                   fsa_cib_conn->cmds->set_connection_dnotify(fsa_cib_conn,
                                                              crmd_cib_connection_destroy)) {
            crm_err("Could not set dnotify callback");

        } else if (pcmk_ok !=
                   fsa_cib_conn->cmds->add_notify_callback(fsa_cib_conn, T_CIB_REPLACE_NOTIFY,
                                                           do_cib_replaced)) {
            crm_err("Could not set CIB notification callback (replace)");

        } else if (pcmk_ok !=
                   fsa_cib_conn->cmds->add_notify_callback(fsa_cib_conn, T_CIB_DIFF_NOTIFY,
                                                           do_cib_updated)) {
            crm_err("Could not set CIB notification callback (update)");

        } else {
            set_bit(fsa_input_register, R_CIB_CONNECTED);
        }

        if (is_set(fsa_input_register, R_CIB_CONNECTED) == FALSE) {

            cib_retries++;
            crm_warn("Couldn't complete CIB registration %d"
                     " times... pause and retry", cib_retries);

            if (cib_retries < 30) {
                crm_timer_start(wait_timer);
                crmd_fsa_stall(NULL);

            } else {
                crm_err("Could not complete CIB"
                        " registration  %d times..." " hard error", cib_retries);
                register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
            }
        } else {
            int call_id = 0;

            crm_info("CIB connection established");

            call_id = fsa_cib_conn->cmds->query(fsa_cib_conn, NULL, NULL, cib_scope_local);

            add_cib_op_callback(fsa_cib_conn, call_id, FALSE, NULL, revision_check_callback);
            cib_retries = 0;
        }
    }
}
