/*
 * Copyright 2009-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
*/

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

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

    match = get_xpath_object((const char *) xpath->str, local_cib, LOG_NEVER);

    g_string_free(xpath, TRUE);
    return (match != NULL);
}

static void
add_topology_level(xmlNode *match)
{
    char *desc = NULL;
    pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

    CRM_CHECK(match != NULL, return);

    fenced_register_level(match, &desc, &result);
    fenced_send_config_notification(STONITH_OP_LEVEL_ADD, &result, desc);
    pcmk__reset_result(&result);
    free(desc);
}

static void
topology_remove_helper(const char *node, int level)
{
    char *desc = NULL;
    pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;
    xmlNode *data = pcmk__xe_create(NULL, PCMK_XE_FENCING_LEVEL);

    crm_xml_add(data, PCMK__XA_ST_ORIGIN, __func__);
    crm_xml_add_int(data, PCMK_XA_INDEX, level);
    crm_xml_add(data, PCMK_XA_TARGET, node);

    fenced_unregister_level(data, &desc, &result);
    fenced_send_config_notification(STONITH_OP_LEVEL_DEL, &result, desc);
    pcmk__reset_result(&result);
    pcmk__xml_free(data);
    free(desc);
}

static void
remove_topology_level(xmlNode *match)
{
    int index = 0;
    char *key = NULL;

    CRM_CHECK(match != NULL, return);

    key = stonith_level_key(match, fenced_target_by_unknown);
    crm_element_value_int(match, PCMK_XA_INDEX, &index);
    topology_remove_helper(key, index);
    free(key);
}

static void
register_fencing_topology(xmlXPathObjectPtr xpathObj)
{
    int max = pcmk__xpath_num_nodes(xpathObj);

    for (int lpc = 0; lpc < max; lpc++) {
        xmlNode *match = pcmk__xpath_result_element(xpathObj, lpc);

        remove_topology_level(match);
        add_topology_level(match);
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
    xmlXPathObjectPtr xpathObj = NULL;

    CRM_CHECK(local_cib != NULL, return);

    crm_trace("Full topology refresh");
    free_topology_list();
    init_topology_list();

    /* Grab everything */
    xpathObj = pcmk__xpath_search(local_cib->doc, "//" PCMK_XE_FENCING_LEVEL);
    register_fencing_topology(xpathObj);

    freeXpathObject(xpathObj);
}

static void
remove_cib_device(xmlXPathObjectPtr xpathObj)
{
    int max = pcmk__xpath_num_nodes(xpathObj);

    for (int lpc = 0; lpc < max; lpc++) {
        const char *rsc_id = NULL;
        const char *standard = NULL;
        xmlNode *match = pcmk__xpath_result_element(xpathObj, lpc);

        CRM_LOG_ASSERT(match != NULL);
        if(match != NULL) {
            standard = crm_element_value(match, PCMK_XA_CLASS);
        }

        if (!pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
            continue;
        }

        rsc_id = crm_element_value(match, PCMK_XA_ID);

        stonith_device_remove(rsc_id, true);
    }
}

#define XPATH_WATCHDOG_TIMEOUT "//" PCMK_XE_NVPAIR      \
                               "[@" PCMK_XA_NAME "='"   \
                                    PCMK_OPT_STONITH_WATCHDOG_TIMEOUT "']"

static void
update_stonith_watchdog_timeout_ms(xmlNode *cib)
{
    long long timeout_ms = 0;
    xmlNode *stonith_watchdog_xml = NULL;
    const char *value = NULL;

    stonith_watchdog_xml = get_xpath_object(XPATH_WATCHDOG_TIMEOUT, cib,
                                            LOG_NEVER);
    if (stonith_watchdog_xml) {
        value = crm_element_value(stonith_watchdog_xml, PCMK_XA_VALUE);
    }
    if (value) {
        timeout_ms = crm_get_msec(value);
    }

    if (timeout_ms < 0) {
        timeout_ms = pcmk__auto_stonith_watchdog_timeout();
    }

    stonith_watchdog_timeout_ms = timeout_ms;
}

/*!
 * \internal
 * \brief Update all STONITH device definitions based on current CIB
 */
static void
cib_devices_update(void)
{
    GHashTableIter iter;
    stonith_device_t *device = NULL;

    crm_info("Updating devices to version %s.%s.%s",
             crm_element_value(local_cib, PCMK_XA_ADMIN_EPOCH),
             crm_element_value(local_cib, PCMK_XA_EPOCH),
             crm_element_value(local_cib, PCMK_XA_NUM_UPDATES));

    g_hash_table_iter_init(&iter, device_list);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&device)) {
        if (device->cib_registered) {
            device->dirty = TRUE;
        }
    }

    /* have list repopulated if cib has a watchdog-fencing-resource
       TODO: keep a cached list for queries happening while we are refreshing
     */
    g_list_free_full(stonith_watchdog_targets, free);
    stonith_watchdog_targets = NULL;

    fenced_scheduler_run(local_cib);

    g_hash_table_iter_init(&iter, device_list);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&device)) {
        if (device->dirty) {
            g_hash_table_iter_remove(&iter);
        }
    }
}

static void
update_cib_stonith_devices_v1(const char *event, xmlNode * msg)
{
    const char *reason = "none";
    gboolean needs_update = FALSE;
    xmlXPathObjectPtr xpath_obj = NULL;

    /* process new constraints */
    xpath_obj = pcmk__xpath_search(msg->doc,
                                   "//" PCMK__XE_CIB_UPDATE_RESULT
                                   "//" PCMK_XE_RSC_LOCATION);
    if (pcmk__xpath_num_nodes(xpath_obj) > 0) {
        int max = pcmk__xpath_num_nodes(xpath_obj);

        /* Safest and simplest to always recompute */
        needs_update = TRUE;
        reason = "new location constraint";

        for (int lpc = 0; lpc < max; lpc++) {
            xmlNode *match = pcmk__xpath_result_element(xpath_obj, lpc);

            crm_log_xml_trace(match, "new constraint");
        }
    }
    freeXpathObject(xpath_obj);

    /* process deletions */
    xpath_obj = pcmk__xpath_search(msg->doc,
                                   "//" PCMK__XE_CIB_UPDATE_RESULT
                                   "//" PCMK__XE_DIFF_REMOVED
                                   "//" PCMK_XE_PRIMITIVE);
    if (pcmk__xpath_num_nodes(xpath_obj) > 0) {
        remove_cib_device(xpath_obj);
    }
    freeXpathObject(xpath_obj);

    /* process additions */
    xpath_obj = pcmk__xpath_search(msg->doc,
                                   "//" PCMK__XE_CIB_UPDATE_RESULT
                                   "//" PCMK__XE_DIFF_ADDED
                                   "//" PCMK_XE_PRIMITIVE);
    if (pcmk__xpath_num_nodes(xpath_obj) > 0) {
        int max = pcmk__xpath_num_nodes(xpath_obj);

        for (int lpc = 0; lpc < max; lpc++) {
            const char *rsc_id = NULL;
            const char *standard = NULL;
            xmlNode *match = pcmk__xpath_result_element(xpath_obj, lpc);

            rsc_id = crm_element_value(match, PCMK_XA_ID);
            standard = crm_element_value(match, PCMK_XA_CLASS);

            if (!pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
                continue;
            }

            crm_trace("Fencing resource %s was added or modified", rsc_id);
            reason = "new resource";
            needs_update = TRUE;
        }
    }
    freeXpathObject(xpath_obj);

    if(needs_update) {
        crm_info("Updating device list from CIB: %s", reason);
        cib_devices_update();
    }
}

static void
update_cib_stonith_devices_v2(const char *event, xmlNode * msg)
{
    xmlNode *change = NULL;
    char *reason = NULL;
    xmlNode *wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_UPDATE_RESULT,
                                            NULL, NULL);
    xmlNode *patchset = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    for (change = pcmk__xe_first_child(patchset, NULL, NULL, NULL);
         change != NULL; change = pcmk__xe_next(change)) {

        const char *op = crm_element_value(change, PCMK_XA_OPERATION);
        const char *xpath = crm_element_value(change, PCMK_XA_PATH);
        const char *shortpath = NULL;

        if (pcmk__str_eq(op, PCMK_VALUE_MOVE, pcmk__str_null_matches)
            || (strstr(xpath, "/" PCMK_XE_STATUS) != NULL)) {
            continue;
        }

        if (pcmk__str_eq(op, PCMK_VALUE_DELETE, pcmk__str_none)
            && (strstr(xpath, "/" PCMK_XE_PRIMITIVE) != NULL)) {
            const char *rsc_id = NULL;
            char *search = NULL;
            char *mutable = NULL;

            if ((strstr(xpath, PCMK_XE_INSTANCE_ATTRIBUTES) != NULL)
                || (strstr(xpath, PCMK_XE_META_ATTRIBUTES) != NULL)) {

                reason = pcmk__str_copy("(meta) attribute deleted from "
                                        "resource");
                break;
            }
            mutable = pcmk__str_copy(xpath);
            rsc_id = strstr(mutable, PCMK_XE_PRIMITIVE "[@" PCMK_XA_ID "=\'");
            if (rsc_id != NULL) {
                rsc_id += strlen(PCMK_XE_PRIMITIVE "[@" PCMK_XA_ID "=\'");
                search = strchr(rsc_id, '\'');
            }
            if (search != NULL) {
                *search = 0;
                stonith_device_remove(rsc_id, true);
                /* watchdog_device_update called afterwards
                   to fall back to implicit definition if needed */
            } else {
                crm_warn("Ignoring malformed CIB update (resource deletion)");
            }
            free(mutable);

        } else if (strstr(xpath, "/" PCMK_XE_RESOURCES)
                   || strstr(xpath, "/" PCMK_XE_CONSTRAINTS)
                   || strstr(xpath, "/" PCMK_XE_RSC_DEFAULTS)) {
            shortpath = strrchr(xpath, '/'); CRM_ASSERT(shortpath);
            reason = crm_strdup_printf("%s %s", op, shortpath+1);
            break;
        }
    }

    if (reason != NULL) {
        crm_info("Updating device list from CIB: %s", reason);
        cib_devices_update();
        free(reason);
    } else {
        crm_trace("No updates for device list found in CIB");
    }
}

static void
update_cib_stonith_devices(const char *event, xmlNode * msg)
{
    int format = 1;
    xmlNode *wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_UPDATE_RESULT,
                                            NULL, NULL);
    xmlNode *patchset = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    CRM_ASSERT(patchset);
    crm_element_value_int(patchset, PCMK_XA_FORMAT, &format);
    switch(format) {
        case 1:
            update_cib_stonith_devices_v1(event, msg);
            break;
        case 2:
            update_cib_stonith_devices_v2(event, msg);
            break;
        default:
            crm_warn("Unknown patch format: %d", format);
    }
}

static void
watchdog_device_update(void)
{
    if (stonith_watchdog_timeout_ms > 0) {
        if (!g_hash_table_lookup(device_list, STONITH_WATCHDOG_ID) &&
            !stonith_watchdog_targets) {
            /* getting here watchdog-fencing enabled, no device there yet
               and reason isn't stonith_watchdog_targets preventing that
             */
            int rc;
            xmlNode *xml;

            xml = create_device_registration_xml(
                    STONITH_WATCHDOG_ID,
                    st_namespace_internal,
                    STONITH_WATCHDOG_AGENT,
                    NULL, /* stonith_device_register will add our
                             own name as PCMK_STONITH_HOST_LIST param
                             so we can skip that here
                           */
                    NULL);
            rc = stonith_device_register(xml, TRUE);
            pcmk__xml_free(xml);
            if (rc != pcmk_ok) {
                rc = pcmk_legacy2rc(rc);
                exit_code = CRM_EX_FATAL;
                crm_crit("Cannot register watchdog pseudo fence agent: %s",
                         pcmk_rc_str(rc));
                stonith_shutdown(0);
            }
        }

    } else if (g_hash_table_lookup(device_list, STONITH_WATCHDOG_ID) != NULL) {
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

    crm_trace("Re-requesting full CIB");
    rc = cib_api->cmds->query(cib_api, NULL, &local_cib,
                              cib_scope_local|cib_sync_call);
    rc = pcmk_legacy2rc(rc);
    if (rc == pcmk_rc_ok) {
        CRM_ASSERT(local_cib != NULL);
    } else {
        crm_err("Couldn't retrieve the CIB: %s " CRM_XS " rc=%d",
                pcmk_rc_str(rc), rc);
    }
    return rc;
}

static void
remove_fencing_topology(xmlXPathObjectPtr xpathObj)
{
    int max = pcmk__xpath_num_nodes(xpathObj);

    for (int lpc = 0; lpc < max; lpc++) {
        xmlNode *match = pcmk__xpath_result_element(xpathObj, lpc);

        CRM_LOG_ASSERT(match != NULL);
        if (match && crm_element_value(match, PCMK__XA_CRM_DIFF_MARKER)) {
            /* Deletion */
            int index = 0;
            char *target = stonith_level_key(match, fenced_target_by_unknown);

            crm_element_value_int(match, PCMK_XA_INDEX, &index);
            if (target == NULL) {
                crm_err("Invalid fencing target in element %s",
                        pcmk__xe_id(match));

            } else if (index <= 0) {
                crm_err("Invalid level for %s in element %s",
                        target, pcmk__xe_id(match));

            } else {
                topology_remove_helper(target, index);
            }
            /* } else { Deal with modifications during the 'addition' stage */
        }
    }
}

static void
update_fencing_topology(const char *event, xmlNode * msg)
{
    int format = 1;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode *wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_UPDATE_RESULT,
                                            NULL, NULL);
    xmlNode *patchset = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    CRM_ASSERT(patchset);
    crm_element_value_int(patchset, PCMK_XA_FORMAT, &format);

    if(format == 1) {
        /* Process deletions (only) */
        xpathObj = pcmk__xpath_search(msg->doc,
                                      "//" PCMK__XE_CIB_UPDATE_RESULT
                                      "//" PCMK__XE_DIFF_REMOVED
                                      "//" PCMK_XE_FENCING_LEVEL);

        remove_fencing_topology(xpathObj);
        freeXpathObject(xpathObj);

        /* Process additions and changes */
        xpathObj = pcmk__xpath_search(msg->doc,
                                      "//" PCMK__XE_CIB_UPDATE_RESULT
                                      "//" PCMK__XE_DIFF_ADDED
                                      "//" PCMK_XE_FENCING_LEVEL);

        register_fencing_topology(xpathObj);
        freeXpathObject(xpathObj);

    } else if(format == 2) {
        xmlNode *change = NULL;
        int add[] = { 0, 0, 0 };
        int del[] = { 0, 0, 0 };

        xml_patch_versions(patchset, add, del);

        for (change = pcmk__xe_first_child(patchset, NULL, NULL, NULL);
             change != NULL; change = pcmk__xe_next(change)) {

            const char *op = crm_element_value(change, PCMK_XA_OPERATION);
            const char *xpath = crm_element_value(change, PCMK_XA_PATH);

            if(op == NULL) {
                continue;

            } else if(strstr(xpath, "/" PCMK_XE_FENCING_LEVEL) != NULL) {
                /* Change to a specific entry */

                crm_trace("Handling %s operation %d.%d.%d for %s", op, add[0], add[1], add[2], xpath);
                if (strcmp(op, PCMK_VALUE_MOVE) == 0) {
                    continue;

                } else if (strcmp(op, PCMK_VALUE_CREATE) == 0) {
                    add_topology_level(change->children);

                } else if (strcmp(op, PCMK_VALUE_MODIFY) == 0) {
                    xmlNode *match = pcmk__xe_first_child(change,
                                                          PCMK_XE_CHANGE_RESULT,
                                                          NULL, NULL);

                    if(match) {
                        remove_topology_level(match->children);
                        add_topology_level(match->children);
                    }

                } else if (strcmp(op, PCMK_VALUE_DELETE) == 0) {
                    /* Nuclear option, all we have is the path and an id... not enough to remove a specific entry */
                    crm_info("Re-initializing fencing topology after %s operation %d.%d.%d for %s",
                             op, add[0], add[1], add[2], xpath);
                    fencing_topology_init();
                    return;
                }

            } else if (strstr(xpath, "/" PCMK_XE_FENCING_TOPOLOGY) != NULL) {
                /* Change to the topology in general */
                crm_info("Re-initializing fencing topology after top-level %s operation  %d.%d.%d for %s",
                         op, add[0], add[1], add[2], xpath);
                fencing_topology_init();
                return;

            } else if (strstr(xpath, "/" PCMK_XE_CONFIGURATION)) {
                /* Changes to the whole config section, possibly including the topology as a whild */
                if (pcmk__xe_first_child(change, PCMK_XE_FENCING_TOPOLOGY, NULL,
                                         NULL) == NULL) {
                    crm_trace("Nothing for us in %s operation %d.%d.%d for %s.",
                              op, add[0], add[1], add[2], xpath);

                } else if (pcmk__str_any_of(op,
                                            PCMK_VALUE_DELETE,
                                            PCMK_VALUE_CREATE, NULL)) {
                    crm_info("Re-initializing fencing topology after top-level %s operation %d.%d.%d for %s.",
                             op, add[0], add[1], add[2], xpath);
                    fencing_topology_init();
                    return;
                }

            } else {
                crm_trace("Nothing for us in %s operation %d.%d.%d for %s",
                          op, add[0], add[1], add[2], xpath);
            }
        }

    } else {
        crm_warn("Unknown patch format: %d", format);
    }
}

static void
update_cib_cache_cb(const char *event, xmlNode * msg)
{
    long long timeout_ms_saved = stonith_watchdog_timeout_ms;
    bool need_full_refresh = false;

    if(!have_cib_devices) {
        crm_trace("Skipping updates until we get a full dump");
        return;

    } else if(msg == NULL) {
        crm_trace("Missing %s update", event);
        return;
    }

    /* Maintain a local copy of the CIB so that we have full access
     * to device definitions, location constraints, and node attributes
     */
    if (local_cib != NULL) {
        int rc = pcmk_ok;
        xmlNode *wrapper = NULL;
        xmlNode *patchset = NULL;

        crm_element_value_int(msg, PCMK__XA_CIB_RC, &rc);
        if (rc != pcmk_ok) {
            return;
        }

        wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_UPDATE_RESULT, NULL,
                                       NULL);
        patchset = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

        rc = xml_apply_patchset(local_cib, patchset, TRUE);
        switch (rc) {
            case pcmk_ok:
            case -pcmk_err_old_data:
                break;
            case -pcmk_err_diff_resync:
            case -pcmk_err_diff_failed:
                crm_notice("[%s] Patch aborted: %s (%d)", event, pcmk_strerror(rc), rc);
                pcmk__xml_free(local_cib);
                local_cib = NULL;
                break;
            default:
                crm_warn("[%s] ABORTED: %s (%d)", event, pcmk_strerror(rc), rc);
                pcmk__xml_free(local_cib);
                local_cib = NULL;
        }
    }

    if (local_cib == NULL) {
        if (fenced_query_cib() != pcmk_rc_ok) {
            return;
        }
        need_full_refresh = true;
    }

    pcmk__refresh_node_caches_from_cib(local_cib);
    update_stonith_watchdog_timeout_ms(local_cib);

    if (timeout_ms_saved != stonith_watchdog_timeout_ms) {
        need_full_refresh = true;
    }

    if (need_full_refresh) {
        fencing_topology_init();
        cib_devices_update();
    } else {
        // Partial refresh
        update_fencing_topology(event, msg);
        update_cib_stonith_devices(event, msg);
    }

    watchdog_device_update();
}

static void
init_cib_cache_cb(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    crm_info("Updating device list from CIB");
    have_cib_devices = TRUE;
    local_cib = pcmk__xml_copy(NULL, output);

    pcmk__refresh_node_caches_from_cib(local_cib);
    update_stonith_watchdog_timeout_ms(local_cib);

    fencing_topology_init();
    cib_devices_update();
    watchdog_device_update();
}

static void
cib_connection_destroy(gpointer user_data)
{
    if (stonith_shutdown_flag) {
        crm_info("Connection to the CIB manager closed");
        return;
    } else {
        crm_crit("Lost connection to the CIB manager, shutting down");
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
        crm_err("No connection to the CIB manager");
        return;
    }

    do {
        sleep(retries);
        rc = cib_api->cmds->signon(cib_api, CRM_SYSTEM_STONITHD, cib_command);
    } while (rc == -ENOTCONN && ++retries < 5);

    if (rc != pcmk_ok) {
        crm_err("Could not connect to the CIB manager: %s (%d)", pcmk_strerror(rc), rc);
        return;
    }

    rc = cib_api->cmds->add_notify_callback(cib_api,
                                            PCMK__VALUE_CIB_DIFF_NOTIFY,
                                            update_cib_cache_cb);
    if (rc != pcmk_ok) {
        crm_err("Could not set CIB notification callback");
        return;
    }

    rc = cib_api->cmds->query(cib_api, NULL, NULL, cib_scope_local);
    cib_api->cmds->register_callback(cib_api, rc, 120, FALSE, NULL,
                                     "init_cib_cache_cb", init_cib_cache_cb);
    cib_api->cmds->set_connection_dnotify(cib_api, cib_connection_destroy);
    crm_info("Watching for fencing topology changes");
}
