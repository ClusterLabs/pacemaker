/*
 * Copyright 2009-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
*/

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <libxml/tree.h>            // xmlNode
#include <libxml/xpath.h>           // xmlXPathObject, etc.

#include <crm/crm.h>
#include <crm/common/xml.h>

#include <crm/cluster/internal.h>

#include <crm/cib.h>
#include <crm/cib/internal.h>

#include <pacemaker-fenced.h>

static xmlNode *local_cib = NULL;
static cib_t *cib_api = NULL;
static bool have_cib_devices = FALSE;

/*!
 * \internal
 * \brief Check whether a node has a specific attribute name/value
 *
 * \param[in] node    Name of node to check
 * \param[in] name    Name of an attribute to look for
 * \param[in] value   The value the named attribute needs to be set to in order to be considered a match
 *
 * \return TRUE if the locally cached CIB has the specified node attribute
 */
gboolean
node_has_attr(const char *node, const char *name, const char *value)
{
    GString *xpath = NULL;
    xmlNode *match;

    CRM_CHECK((local_cib != NULL) && (node != NULL) && (name != NULL)
              && (value != NULL), return FALSE);

    /* Search for the node's attributes in the CIB. While the schema allows
     * multiple sets of instance attributes, and allows instance attributes to
     * use id-ref to reference values elsewhere, that is intended for resources,
     * so we ignore that here.
     */
    xpath = g_string_sized_new(256);
    pcmk__g_strcat(xpath,
                   "//" PCMK_XE_NODES "/" PCMK_XE_NODE
                   "[@" PCMK_XA_UNAME "='", node, "']"
                   "/" PCMK_XE_INSTANCE_ATTRIBUTES
                   "/" PCMK_XE_NVPAIR
                   "[@" PCMK_XA_NAME "='", name, "' "
                   "and @" PCMK_XA_VALUE "='", value, "']", NULL);

    match = pcmk__xpath_find_one(local_cib->doc, xpath->str, PCMK__LOG_NEVER);

    g_string_free(xpath, TRUE);
    return (match != NULL);
}

static void
remove_topology_level(xmlNode *match)
{
    int index = 0;
    char *key = NULL;
    xmlNode *data = NULL;

    CRM_CHECK(match != NULL, return);

    key = stonith_level_key(match, fenced_target_by_unknown);
    pcmk__xe_get_int(match, PCMK_XA_INDEX, &index);

    data = pcmk__xe_create(NULL, PCMK_XE_FENCING_LEVEL);
    pcmk__xe_set(data, PCMK__XA_ST_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK_XA_TARGET, key);
    pcmk__xe_set_int(data, PCMK_XA_INDEX, index);

    fenced_unregister_level(data, NULL);

    free(key);
    pcmk__xml_free(data);
}

static void
register_fencing_topology(xmlXPathObjectPtr xpathObj)
{
    int max = pcmk__xpath_num_results(xpathObj);

    for (int lpc = 0; lpc < max; lpc++) {
        xmlNode *match = pcmk__xpath_result(xpathObj, lpc);

        if (match == NULL) {
            continue;
        }
        remove_topology_level(match);
        fenced_register_level(match, NULL);
    }
}

/* Fencing
<diff crm_feature_set="3.0.6">
  <diff-removed>
    <fencing-topology>
      <fencing-level id="f-p1.1" target="pcmk-1" index="1" devices="poison-pill" __crm_diff_marker__="removed:top"/>
      <fencing-level id="f-p1.2" target="pcmk-1" index="2" devices="power" __crm_diff_marker__="removed:top"/>
      <fencing-level devices="disk,network" id="f-p2.1"/>
    </fencing-topology>
  </diff-removed>
  <diff-added>
    <fencing-topology>
      <fencing-level id="f-p.1" target="pcmk-1" index="1" devices="poison-pill" __crm_diff_marker__="added:top"/>
      <fencing-level id="f-p2.1" target="pcmk-2" index="1" devices="disk,something"/>
      <fencing-level id="f-p3.1" target="pcmk-2" index="2" devices="power" __crm_diff_marker__="added:top"/>
    </fencing-topology>
  </diff-added>
</diff>
*/

void
fencing_topology_init(void)
{
    xmlXPathObject *xpathObj = NULL;
    const char *xpath = "//" PCMK_XE_FENCING_LEVEL;

    pcmk__trace("Full topology refresh");
    free_topology_list();
    init_topology_list();

    /* Grab everything */
    xpathObj = pcmk__xpath_search(local_cib->doc, xpath);
    register_fencing_topology(xpathObj);

    xmlXPathFreeObject(xpathObj);
}

#define XPATH_WATCHDOG_TIMEOUT "//" PCMK_XE_NVPAIR      \
                               "[@" PCMK_XA_NAME "='"   \
                                    PCMK_OPT_FENCING_WATCHDOG_TIMEOUT "']"

static void
update_fencing_watchdog_timeout_ms(xmlNode *cib)
{
    xmlNode *stonith_watchdog_xml = NULL;
    const char *value = NULL;
    int rc = pcmk_rc_ok;

    // @TODO An XPath search can't handle multiple instances or rules
    stonith_watchdog_xml = pcmk__xpath_find_one(cib->doc,
                                                XPATH_WATCHDOG_TIMEOUT,
                                                PCMK__LOG_NEVER);
    if (stonith_watchdog_xml == NULL) {
        return;
    }

    value = pcmk__xe_get(stonith_watchdog_xml, PCMK_XA_VALUE);
    if (value == NULL) {
        return;
    }

    rc = pcmk__parse_ms(value, &fencing_watchdog_timeout_ms);

    if ((rc != pcmk_rc_ok) || (fencing_watchdog_timeout_ms < 0)) {
        fencing_watchdog_timeout_ms = pcmk__auto_fencing_watchdog_timeout();
    }
}

/*!
 * \internal
 * \brief Mark a fence device dirty if its \c fenced_df_cib_registered flag is
 *        set
 *
 * \param[in]     key        Ignored
 * \param[in,out] value      Fence device (<tt>fenced_device_t *</tt>)
 * \param[in]     user_data  Ignored
 *
 * \note This function is suitable for use with \c g_hash_table_foreach().
 */
static void
mark_dirty_if_cib_registered(gpointer key, gpointer value, gpointer user_data)
{
    fenced_device_t *device = value;

    if (pcmk__is_set(device->flags, fenced_df_cib_registered)) {
        fenced_device_set_flags(device, fenced_df_dirty);
    }
}

/*!
 * \internal
 * \brief Return the value of a fence device's \c dirty flag
 *
 * \param[in] key        Ignored
 * \param[in] value      Fence device (<tt>fenced_device_t *</tt>)
 * \param[in] user_data  Ignored
 *
 * \return \c dirty flag of \p value
 *
 * \note This function is suitable for use with
 *       \c g_hash_table_foreach_remove().
 */
static gboolean
device_is_dirty(gpointer key, gpointer value, gpointer user_data)
{
    fenced_device_t *device = value;

    return pcmk__is_set(device->flags, fenced_df_dirty);
}

/*!
 * \internal
 * \brief Update all STONITH device definitions based on current CIB
 */
static void
cib_devices_update(void)
{
    pcmk__info("Updating devices to version %s.%s.%s",
               pcmk__xe_get(local_cib, PCMK_XA_ADMIN_EPOCH),
               pcmk__xe_get(local_cib, PCMK_XA_EPOCH),
               pcmk__xe_get(local_cib, PCMK_XA_NUM_UPDATES));

    fenced_foreach_device(mark_dirty_if_cib_registered, NULL);

    /* have list repopulated if cib has a watchdog-fencing-resource
       TODO: keep a cached list for queries happening while we are refreshing
     */
    g_list_free_full(stonith_watchdog_targets, free);
    stonith_watchdog_targets = NULL;

    fenced_scheduler_run(local_cib);

    fenced_foreach_device_remove(device_is_dirty);
}

#define PRIMITIVE_ID_XP_FRAGMENT "/" PCMK_XE_PRIMITIVE "[@" PCMK_XA_ID "='"

static void
update_cib_stonith_devices(const xmlNode *patchset)
{
    char *reason = NULL;

    for (const xmlNode *change = pcmk__xe_first_child(patchset, NULL, NULL,
                                                      NULL);
         change != NULL; change = pcmk__xe_next(change, NULL)) {

        const char *op = pcmk__xe_get(change, PCMK_XA_OPERATION);
        const char *xpath = pcmk__xe_get(change, PCMK_XA_PATH);
        const char *primitive_xpath = NULL;

        if (pcmk__str_eq(op, PCMK_VALUE_MOVE, pcmk__str_null_matches)
            || (strstr(xpath, "/" PCMK_XE_STATUS) != NULL)) {
            continue;
        }

        primitive_xpath = strstr(xpath, PRIMITIVE_ID_XP_FRAGMENT);
        if ((primitive_xpath != NULL)
            && pcmk__str_eq(op, PCMK_VALUE_DELETE, pcmk__str_none)) {

            const char *rsc_id = NULL;
            const char *end_quote = NULL;

            if ((strstr(primitive_xpath, PCMK_XE_INSTANCE_ATTRIBUTES) != NULL)
                || (strstr(primitive_xpath, PCMK_XE_META_ATTRIBUTES) != NULL)) {

                reason = pcmk__str_copy("(meta) attribute deleted from "
                                        "resource");
                break;
            }

            rsc_id = primitive_xpath + sizeof(PRIMITIVE_ID_XP_FRAGMENT) - 1;
            end_quote = strchr(rsc_id, '\'');

            CRM_LOG_ASSERT(end_quote != NULL);
            if (end_quote == NULL) {
                pcmk__err("Bug: Malformed item in Pacemaker-generated patchset");
                continue;
            }

            if (strchr(end_quote, '/') == NULL) {
                /* The primitive element itself was deleted. If this was a
                 * fencing resource, it's faster to remove it directly than to
                 * run the scheduler and update all device registrations.
                */
                char *copy = strndup(rsc_id, end_quote - rsc_id);

                pcmk__assert(copy != NULL);
                stonith_device_remove(copy, true);

                /* watchdog_device_update called afterwards
                   to fall back to implicit definition if needed */

                free(copy);
                continue;
            }
        }

        if (strstr(xpath, "/" PCMK_XE_RESOURCES)
            || strstr(xpath, "/" PCMK_XE_CONSTRAINTS)
            || strstr(xpath, "/" PCMK_XE_RSC_DEFAULTS)) {

            const char *shortpath = strrchr(xpath, '/');

            reason = pcmk__assert_asprintf("%s %s", op, shortpath + 1);
            break;
        }
    }

    if (reason != NULL) {
        pcmk__info("Updating device list from CIB: %s", reason);
        cib_devices_update();
        free(reason);
    } else {
        pcmk__trace("No updates for device list found in CIB");
    }
}

static void
watchdog_device_update(void)
{
    if (fencing_watchdog_timeout_ms > 0) {
        if (!fenced_has_watchdog_device()
            && (stonith_watchdog_targets == NULL)) {
            /* getting here watchdog-fencing enabled, no device there yet
               and reason isn't stonith_watchdog_targets preventing that
             */
            int rc;
            xmlNode *xml;

            xml = create_device_registration_xml(
                    STONITH_WATCHDOG_ID,
                    st_namespace_internal,
                    STONITH_WATCHDOG_AGENT,
                    NULL, /* fenced_device_register() will add our
                             own name as PCMK_FENCING_HOST_LIST param
                             so we can skip that here
                           */
                    NULL);
            rc = fenced_device_register(xml, true);
            pcmk__xml_free(xml);
            if (rc != pcmk_rc_ok) {
                exit_code = CRM_EX_FATAL;
                pcmk__crit("Cannot register watchdog pseudo fence agent: %s",
                           pcmk_rc_str(rc));
                stonith_shutdown(0);
            }
        }

    } else if (fenced_has_watchdog_device()) {
        /* be silent if no device - todo parameter to stonith_device_remove */
        stonith_device_remove(STONITH_WATCHDOG_ID, true);
    }
}

/*!
 * \internal
 * \brief Query the full CIB
 *
 * \return Standard Pacemaker return code
 */
static int
fenced_query_cib(void)
{
    int rc = pcmk_ok;

    pcmk__trace("Re-requesting full CIB");
    rc = cib_api->cmds->query(cib_api, NULL, &local_cib, cib_sync_call);
    rc = pcmk_legacy2rc(rc);
    if (rc == pcmk_rc_ok) {
        pcmk__assert(local_cib != NULL);
    } else {
        pcmk__err("Couldn't retrieve the CIB: %s " QB_XS " rc=%d",
                  pcmk_rc_str(rc), rc);
    }
    return rc;
}

static void
update_fencing_topology(const char *event, xmlNode *msg)
{
    xmlNode *wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_UPDATE_RESULT,
                                            NULL, NULL);
    xmlNode *patchset = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    int format = 1;

    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };

    CRM_CHECK(patchset != NULL, return);

    pcmk__xe_get_int(patchset, PCMK_XA_FORMAT, &format);
    if (format != 2) {
        pcmk__warn("Unknown patch format: %d", format);
        return;
    }

    pcmk__xml_patchset_versions(patchset, del, add);

    for (xmlNode *change = pcmk__xe_first_child(patchset, NULL, NULL, NULL);
         change != NULL; change = pcmk__xe_next(change, NULL)) {

        const char *op = pcmk__xe_get(change, PCMK_XA_OPERATION);
        const char *xpath = pcmk__xe_get(change, PCMK_XA_PATH);

        if (op == NULL) {
            continue;
        }

        if (strstr(xpath, "/" PCMK_XE_FENCING_LEVEL) != NULL) {
            // Change to a specific entry
            pcmk__trace("Handling %s operation %d.%d.%d for %s", op,
                        add[0], add[1], add[2], xpath);

            if (strcmp(op, PCMK_VALUE_DELETE) == 0) {
                /* We have only path and ID, which is not enough info to remove
                 * a specific entry. Re-initialize the whole topology.
                 */
                pcmk__info("Re-initializing fencing topology after %s "
                           "operation %d.%d.%d for %s",
                           op, add[0], add[1], add[2], xpath);
                fencing_topology_init();
                return;
            }

            if (strcmp(op, PCMK_VALUE_CREATE) == 0) {
                fenced_register_level(change->children, NULL);

            } else if (strcmp(op, PCMK_VALUE_MODIFY) == 0) {
                xmlNode *match = pcmk__xe_first_child(change,
                                                      PCMK_XE_CHANGE_RESULT,
                                                      NULL, NULL);

                if (match != NULL) {
                    remove_topology_level(match->children);
                    fenced_register_level(match->children, NULL);
                }
            }
            continue;
        }

        if (strstr(xpath, "/" PCMK_XE_FENCING_TOPOLOGY) != NULL) {
            // Change to the topology in general
            pcmk__info("Re-initializing fencing topology after top-level %s "
                       "operation %d.%d.%d for %s",
                       op, add[0], add[1], add[2], xpath);
            fencing_topology_init();
            return;
        }

        if ((strstr(xpath, "/" PCMK_XE_CONFIGURATION) != NULL)
            && (pcmk__xe_first_child(change, PCMK_XE_FENCING_TOPOLOGY, NULL,
                                     NULL) != NULL)
            && pcmk__str_any_of(op, PCMK_VALUE_CREATE, PCMK_VALUE_DELETE,
                                NULL)) {

            // Topology was created or entire configuration section was deleted
            pcmk__info("Re-initializing fencing topology after top-level %s "
                       "operation %d.%d.%d for %s",
                       op, add[0], add[1], add[2], xpath);
            fencing_topology_init();
            return;
        }

        pcmk__trace("Nothing for us in %s operation %d.%d.%d for %s", op,
                    add[0], add[1], add[2], xpath);
    }
}

static void
update_cib_cache_cb(const char *event, xmlNode * msg)
{
    xmlNode *patchset = NULL;
    long long timeout_ms_saved = fencing_watchdog_timeout_ms;
    bool need_full_refresh = false;

    if(!have_cib_devices) {
        pcmk__trace("Skipping updates until we get a full dump");
        return;

    } else if(msg == NULL) {
        pcmk__trace("Missing %s update", event);
        return;
    }

    /* Maintain a local copy of the CIB so that we have full access
     * to device definitions, location constraints, and node attributes
     */
    if (local_cib != NULL) {
        int rc = pcmk_ok;
        xmlNode *wrapper = NULL;

        pcmk__xe_get_int(msg, PCMK__XA_CIB_RC, &rc);
        if (rc != pcmk_ok) {
            return;
        }

        wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_UPDATE_RESULT, NULL,
                                       NULL);
        patchset = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

        rc = xml_apply_patchset(local_cib, patchset, TRUE);

        if (rc != pcmk_ok) {
            if ((rc == -pcmk_err_old_data) || (rc == -pcmk_err_diff_failed)) {
                pcmk__notice("[%s] Patch aborted: %s (%d)", event,
                             pcmk_strerror(rc), rc);
            } else {
                pcmk__warn("[%s] ABORTED: %s (%d)", event, pcmk_strerror(rc),
                           rc);
            }

            g_clear_pointer(&local_cib, pcmk__xml_free);
        }
    }

    if (local_cib == NULL) {
        if (fenced_query_cib() != pcmk_rc_ok) {
            return;
        }
        need_full_refresh = true;
    }

    pcmk__refresh_node_caches_from_cib(local_cib);
    update_fencing_watchdog_timeout_ms(local_cib);

    if (timeout_ms_saved != fencing_watchdog_timeout_ms) {
        need_full_refresh = true;
    }

    if (need_full_refresh) {
        fencing_topology_init();
        cib_devices_update();
    } else {
        // Partial refresh
        update_fencing_topology(event, msg);
        update_cib_stonith_devices(patchset);
    }

    watchdog_device_update();
}

static void
init_cib_cache_cb(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    pcmk__info("Updating device list from CIB");
    have_cib_devices = TRUE;
    local_cib = pcmk__xml_copy(NULL, output);

    pcmk__refresh_node_caches_from_cib(local_cib);
    update_fencing_watchdog_timeout_ms(local_cib);

    fencing_topology_init();
    cib_devices_update();
    watchdog_device_update();
}

static void
cib_connection_destroy(gpointer user_data)
{
    if (stonith_shutdown_flag) {
        pcmk__info("Connection to the CIB manager closed");
        return;
    } else {
        pcmk__crit("Lost connection to the CIB manager, shutting down");
    }
    if (cib_api) {
        cib_api->cmds->signoff(cib_api);
    }
    stonith_shutdown(0);
}

/*!
 * \internal
 * \brief Disconnect from CIB manager
 */
void
fenced_cib_cleanup(void)
{
    if (cib_api != NULL) {
        cib_api->cmds->del_notify_callback(cib_api, PCMK__VALUE_CIB_DIFF_NOTIFY,
                                           update_cib_cache_cb);
        cib__clean_up_connection(&cib_api);
    }
    pcmk__xml_free(local_cib);
    local_cib = NULL;
}

void
setup_cib(void)
{
    int rc, retries = 0;

    cib_api = cib_new();
    if (cib_api == NULL) {
        pcmk__err("No connection to the CIB manager");
        return;
    }

    do {
        sleep(retries);
        rc = cib_api->cmds->signon(cib_api, crm_system_name, cib_command);
    } while (rc == -ENOTCONN && ++retries < 5);

    if (rc != pcmk_ok) {
        pcmk__err("Could not connect to the CIB manager: %s (%d)",
                  pcmk_strerror(rc), rc);
        return;
    }

    rc = cib_api->cmds->add_notify_callback(cib_api,
                                            PCMK__VALUE_CIB_DIFF_NOTIFY,
                                            update_cib_cache_cb);
    if (rc != pcmk_ok) {
        pcmk__err("Could not set CIB notification callback");
        return;
    }

    rc = cib_api->cmds->query(cib_api, NULL, NULL, cib_none);
    cib_api->cmds->register_callback(cib_api, rc, 120, FALSE, NULL,
                                     "init_cib_cache_cb", init_cib_cache_cb);
    cib_api->cmds->set_connection_dnotify(cib_api, cib_connection_destroy);
    pcmk__info("Watching for fencing topology changes");
}
