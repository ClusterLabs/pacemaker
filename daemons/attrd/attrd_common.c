/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <errno.h>
#include <glib.h>
#include <regex.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/common/ipcs.h>
#include <crm/common/mainloop.h>

#include <attrd_common.h>

cib_t *the_cib = NULL;

static gboolean shutting_down = FALSE;
static GMainLoop *mloop = NULL;

/*!
 * \internal
 * \brief Check whether we're currently shutting down
 *
 * \return TRUE if shutting down, FALSE otherwise
 */
gboolean
attrd_shutting_down()
{
    return shutting_down;
}

/*!
 * \internal
 * \brief  Exit (using mainloop or not, as appropriate)
 *
 * \param[in] nsig  Ignored
 */
void
attrd_shutdown(int nsig)
{
    shutting_down = TRUE;
    if ((mloop != NULL) && g_main_is_running(mloop)) {
        g_main_loop_quit(mloop);
    } else {
        crm_exit(CRM_EX_OK);
    }
}

/*!
 * \internal
 * \brief Create a main loop for attrd
 */
void
attrd_init_mainloop()
{
    mloop = g_main_loop_new(NULL, FALSE);
}

/*!
 * \internal
 * \brief Run attrd main loop
 */
void
attrd_run_mainloop()
{
    g_main_loop_run(mloop);
}

/*!
 * \internal
 * \brief Accept a new client IPC connection
 *
 * \param[in] c    New connection
 * \param[in] uid  Client user id
 * \param[in] gid  Client group id
 *
 * \return pcmk_ok on success, -errno otherwise
 */
static int32_t
attrd_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    crm_trace("New client connection %p", c);
    if (shutting_down) {
        crm_info("Ignoring new connection from pid %d during shutdown",
                 crm_ipcs_client_pid(c));
        return -EPERM;
    }

    if (crm_client_new(c, uid, gid) == NULL) {
        return -EIO;
    }
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Callback for successful client connection
 *
 * \param[in] c  New connection
 */
static void
attrd_ipc_created(qb_ipcs_connection_t *c)
{
    crm_trace("Client connection %p accepted", c);
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 *
 * \return FALSE (i.e. do not re-run this callback)
 */
static int32_t
attrd_ipc_closed(qb_ipcs_connection_t *c)
{
    crm_client_t *client = crm_client_get(c);

    if (client == NULL) {
        crm_trace("Ignoring request to clean up unknown connection %p", c);
    } else {
        crm_trace("Cleaning up closed client connection %p", c);
        crm_client_destroy(client);
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 *
 * \note We handle a destroyed connection the same as a closed one,
 *       but we need a separate handler because the return type is different.
 */
static void
attrd_ipc_destroy(qb_ipcs_connection_t *c)
{
    crm_trace("Destroying client connection %p", c);
    attrd_ipc_closed(c);
}

/*!
 * \internal
 * \brief Set up attrd IPC communication
 *
 * \param[out] ipcs         Will be set to newly allocated server connection
 * \param[in]  dispatch_fn  Handler for new messages on connection
 */
void
attrd_init_ipc(qb_ipcs_service_t **ipcs, qb_ipcs_msg_process_fn dispatch_fn)
{

    static struct qb_ipcs_service_handlers ipc_callbacks = {
        .connection_accept = attrd_ipc_accept,
        .connection_created = attrd_ipc_created,
        .msg_process = NULL,
        .connection_closed = attrd_ipc_closed,
        .connection_destroyed = attrd_ipc_destroy
    };

    ipc_callbacks.msg_process = dispatch_fn;
    attrd_ipc_server_init(ipcs, &ipc_callbacks);
}

void
attrd_cib_disconnect()
{
    if (the_cib) {
        the_cib->cmds->signoff(the_cib);
        cib_delete(the_cib);
        the_cib = NULL;
    }
}

/* strlen("value") */
#define plus_plus_len (5)

/*!
 * \internal
 * \brief  Check whether an attribute value should be expanded
 *
 * \param[in] value  Attribute value to check
 *
 * \return TRUE if value needs expansion, FALSE otherwise
 */
gboolean
attrd_value_needs_expansion(const char *value)
{
    return ((strlen(value) >= (plus_plus_len + 2))
           && (value[plus_plus_len] == '+')
           && ((value[plus_plus_len + 1] == '+')
               || (value[plus_plus_len + 1] == '=')));
}

/*!
 * \internal
 * \brief Expand an increment expression into an integer
 *
 * \param[in] value      Attribute increment expression to expand
 * \param[in] old_value  Previous value of attribute
 *
 * \return Expanded value
 */
int
attrd_expand_value(const char *value, const char *old_value)
{
    int offset = 1;
    int int_value = char2score(old_value);

    if (value[plus_plus_len + 1] != '+') {
        const char *offset_s = value + (plus_plus_len + 2);

        offset = char2score(offset_s);
    }
    int_value += offset;

    if (int_value > INFINITY) {
        int_value = INFINITY;
    }
    return int_value;
}

/*!
 * \internal
 * \brief Create regular expression matching failure-related attributes
 *
 * \param[out] regex  Where to store created regular expression
 * \param[in]  rsc    Name of resource to clear (or NULL for all)
 * \param[in]  op     Operation to clear if rsc is specified (or NULL for all)
 * \param[in]  interval_ms  Interval of operation to clear if op is specified
 *
 * \return pcmk_ok on success, -EINVAL if arguments are invalid
 *
 * \note The caller is responsible for freeing the result with regfree().
 */
int
attrd_failure_regex(regex_t *regex, const char *rsc, const char *op,
                    guint interval_ms)
{
    char *pattern = NULL;
    int rc;

    /* Create a pattern that matches desired attributes */

    if (rsc == NULL) {
        pattern = strdup(ATTRD_RE_CLEAR_ALL);
    } else if (op == NULL) {
        pattern = crm_strdup_printf(ATTRD_RE_CLEAR_ONE, rsc);
    } else {
        pattern = crm_strdup_printf(ATTRD_RE_CLEAR_OP, rsc, op, interval_ms);
    }

    /* Compile pattern into regular expression */
    crm_trace("Clearing attributes matching %s", pattern);
    rc = regcomp(regex, pattern, REG_EXTENDED|REG_NOSUB);
    free(pattern);

    return (rc == 0)? pcmk_ok : -EINVAL;
}
