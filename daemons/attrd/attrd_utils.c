/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <glib.h>
#include <regex.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/common/mainloop.h>
#include <crm/common/xml.h>

#include "pacemaker-attrd.h"

cib_t *the_cib = NULL;

static bool shutting_down = false;
static GMainLoop *mloop = NULL;

/* A hash table storing information on the protocol version of each peer attrd.
 * The key is the peer's uname, and the value is the protocol version number.
 */
GHashTable *peer_protocol_vers = NULL;

/*!
 * \internal
 * \brief Check whether local attribute manager is shutting down
 *
 * \return \c true if local attribute manager has begun shutdown sequence,
 *         otherwise \c false
 */
bool
attrd_shutting_down(void)
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
    // Tell various functions not to do anthing
    shutting_down = true;

    attrd_free_waitlist();
    attrd_free_confirmations();

    if (peer_protocol_vers != NULL) {
        g_hash_table_destroy(peer_protocol_vers);
        peer_protocol_vers = NULL;
    }

    // There should be no way to get here without the main loop running
    CRM_CHECK((mloop != NULL) && g_main_loop_is_running(mloop),
              crm_exit(CRM_EX_OK));

    g_main_loop_quit(mloop);
}

/*!
 * \internal
 * \brief Create a main loop for attrd
 */
void
attrd_init_mainloop(void)
{
    mloop = g_main_loop_new(NULL, FALSE);
}

/*!
 * \internal
 * \brief Run attrd main loop
 */
void
attrd_run_mainloop(void)
{
    g_main_loop_run(mloop);
    g_clear_pointer(&mloop, g_main_loop_unref);
}

/* strlen("value") */
#define plus_plus_len (5)

/*!
 * \internal
 * \brief  Check whether an attribute value should be expanded
 *
 * \param[in] value  Attribute value to check
 *
 * \return true if value needs expansion, false otherwise
 */
bool
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
    int increment = 1;
    int score = 0;

    if (pcmk_parse_score(old_value, &score, 0) != pcmk_rc_ok) {
        return 0; // Original value is not a score
    }

    // value++ means increment by one, value+=OFFSET means incremement by OFFSET
    if ((value[plus_plus_len + 1] != '+')
        && (pcmk_parse_score(value + plus_plus_len + 2, &increment,
                             0) != pcmk_rc_ok)) {
        increment = 0; // Invalid increment
    }

    if (increment < 0) {
        return QB_MAX(score + increment, -PCMK_SCORE_INFINITY);
    }
    return QB_MIN(score + increment, PCMK_SCORE_INFINITY);
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
        pattern = pcmk__str_copy(ATTRD_RE_CLEAR_ALL);
    } else if (op == NULL) {
        pattern = pcmk__assert_asprintf(ATTRD_RE_CLEAR_ONE, rsc);
    } else {
        pattern = pcmk__assert_asprintf(ATTRD_RE_CLEAR_OP, rsc, op,
                                        interval_ms);
    }

    /* Compile pattern into regular expression */
    pcmk__trace("Clearing attributes matching %s", pattern);
    rc = regcomp(regex, pattern, REG_EXTENDED|REG_NOSUB);
    free(pattern);

    return (rc == 0)? pcmk_ok : -EINVAL;
}

void
attrd_free_attribute_value(gpointer data)
{
    attribute_value_t *v = data;

    free(v->nodename);
    free(v->current);
    free(v->requested);
    free(v);
}

void
attrd_free_attribute(gpointer data)
{
    attribute_t *a = data;
    if(a) {
        free(a->id);
        free(a->set_id);
        free(a->set_type);
        free(a->user);

        mainloop_timer_del(a->timer);
        g_hash_table_destroy(a->values);

        free(a);
    }
}

/*!
 * \internal
 * \brief When a peer node leaves the cluster, stop tracking its protocol version.
 *
 * \param[in] host  The peer node's uname to be removed
 */
void
attrd_remove_peer_protocol_ver(const char *host)
{
    if (peer_protocol_vers != NULL) {
        g_hash_table_remove(peer_protocol_vers, host);
    }
}

/*!
 * \internal
 * \brief When a peer node broadcasts a message with its protocol version, keep
 *        track of that information.
 *
 * We keep track of each peer's protocol version so we know which peers to
 * expect confirmation messages from when handling cluster-wide sync points.
 * We additionally keep track of the lowest protocol version supported by all
 * peers so we know when we can send IPC messages containing more than one
 * request.
 *
 * \param[in] host  The peer node's uname to be tracked
 * \param[in] value The peer node's protocol version
 */
void
attrd_update_minimum_protocol_ver(const char *host, const char *value)
{
    int ver;

    if (peer_protocol_vers == NULL) {
        peer_protocol_vers = pcmk__strkey_table(free, NULL);
    }

    pcmk__scan_min_int(value, &ver, 0);

    if (ver > 0) {
        /* Record the peer attrd's protocol version. */
        g_hash_table_insert(peer_protocol_vers, pcmk__str_copy(host),
                            GINT_TO_POINTER(ver));

        /* If the protocol version is a new minimum, record it as such. */
        if (minimum_protocol_version == -1 || ver < minimum_protocol_version) {
            minimum_protocol_version = ver;
            pcmk__trace("Set minimum attrd protocol version to %d",
                        minimum_protocol_version);
        }
    }
}
