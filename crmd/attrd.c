/*
 * Copyright (C) 2006-2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/attrd.h>
#include <crm/msg_xml.h>

#include <crmd_fsa.h>
#include <crmd_utils.h>
#include <crmd_messages.h>

crm_ipc_t *attrd_ipc = NULL;

static void
log_attrd_error(const char *host, const char *name, const char *value,
                gboolean is_remote, char command, int rc)
{
    const char *display_command; /* for commands without name/value */
    const char *node_type = (is_remote? "Pacemaker Remote" : "cluster");
    gboolean shutting_down = is_set(fsa_input_register, R_SHUTDOWN);
    const char *when = (shutting_down? " at shutdown" : "");

    switch (command) {
        case 'R':
            display_command = "refresh";
            break;
        case 'C':
            display_command = "purge";
            break;
        default:
            display_command = NULL;
    }

    if (display_command) {
        crm_err("Could not request %s of %s node %s%s: %s (%d)",
                display_command, node_type, host, when, pcmk_strerror(rc), rc);
    } else {
        crm_err("Could not request update of %s=%s for %s node %s%s: %s (%d)",
                name, value, node_type, host, when, pcmk_strerror(rc), rc);
    }

    /* If we can't request shutdown via attribute, fast-track it */
    if ((command == 'U') && shutting_down) {
        register_fsa_input(C_FSA_INTERNAL, I_FAIL, NULL);
    }
}

static void
update_attrd_helper(const char *host, const char *name, const char *value,
                    const char *interval, const char *user_name,
                    gboolean is_remote_node, char command)
{
    int rc;
    int attrd_opts = attrd_opt_none;

    if (is_remote_node) {
        attrd_opts |= attrd_opt_remote;
    }

    if (attrd_ipc == NULL) {
        attrd_ipc = crm_ipc_new(T_ATTRD, 0);
    }

    for (int attempt = 1; attempt <= 4; ++attempt) {
        rc = pcmk_ok;

        // If we're not already connected, try to connect
        if (crm_ipc_connected(attrd_ipc) == FALSE) {
            if (attempt == 1) {
                // Start with a clean slate
                crm_ipc_close(attrd_ipc);
            }
            if (crm_ipc_connect(attrd_ipc) == FALSE) {
                rc = errno;
            }
            crm_debug("Attribute manager connection attempt %d of 4: %s (%d)",
                      attempt, pcmk_strerror(rc), rc);
        }

        if (rc == pcmk_ok) {
            rc = command?
                 attrd_update_delegate(attrd_ipc, command, host, name, value,
                                       XML_CIB_TAG_STATUS, NULL, NULL,
                                       user_name, attrd_opts)

                 /* No command means clear fail count (name/value is really
                  * resource/operation)
                  */
                 : attrd_clear_delegate(attrd_ipc, host, name, value,
                                        interval, user_name, attrd_opts);
            crm_debug("Attribute manager request attempt %d of 4: %s (%d)",
                      attempt, pcmk_strerror(rc), rc);
        }

        if (rc == pcmk_ok) {
            // Success, we're done
            break;

        } else if ((rc != EAGAIN) && (rc != EALREADY)) {
            /* EAGAIN or EALREADY indicates a temporary block, so just try
             * again. Otherwise, close the connection for a clean slate.
             */
            crm_ipc_close(attrd_ipc);
        }

        /* @TODO If the attribute manager remains unavailable the entire time,
         * this function takes more than 6 seconds. Maybe set a timer for
         * retries, to let the main loop do other work.
         */
        if (attempt < 4) {
            sleep(attempt);
        }
    }

    if (rc != pcmk_ok) {
        log_attrd_error(host, name, value, is_remote_node, command, rc);
    }
}

void
update_attrd(const char *host, const char *name, const char *value,
             const char *user_name, gboolean is_remote_node)
{
    update_attrd_helper(host, name, value, NULL, user_name, is_remote_node,
                        'U');
}

void
update_attrd_remote_node_removed(const char *host, const char *user_name)
{
    crm_trace("Asking attrd to purge Pacemaker Remote node %s", host);
    update_attrd_helper(host, NULL, NULL, NULL, user_name, TRUE, 'C');
}

void
update_attrd_clear_failures(const char *host, const char *rsc, const char *op,
                            const char *interval, gboolean is_remote_node)
{
    crm_info("Asking attrd to clear failure of %s %s for %s on %s node %s",
             (op? op : "all operations"),
             (interval? interval : "at all intervals"),
             rsc, (is_remote_node? "Pacemaker Remote" : "cluster"), host);
    update_attrd_helper(host, rsc, op, interval, NULL, is_remote_node, 0);
}
