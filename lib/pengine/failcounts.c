/*
 * Copyright (C) 2008-2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/pengine/internal.h>

struct fail_search {
    resource_t *rsc;
    pe_working_set_t *data_set;
    int count;
    long long last;
    char *key;
};

static void
get_failcount_by_prefix(gpointer key_p, gpointer value, gpointer user_data)
{
    struct fail_search *search = user_data;
    const char *attr_id = key_p;
    const char *match = strstr(attr_id, search->key);
    resource_t *parent = NULL;

    if (match == NULL) {
        return;
    }

    /* we are only incrementing the failcounts here if the rsc
     * that matches our prefix has the same uber parent as the rsc we're
     * calculating the failcounts for. This prevents false positive matches
     * where unrelated resources may have similar prefixes in their names.
     *
     * search->rsc is already set to be the uber parent. */
    parent = uber_parent(pe_find_resource(search->data_set->resources, match));
    if (parent == NULL || parent != search->rsc) {
        return;
    }
    if (strstr(attr_id, CRM_LAST_FAILURE_PREFIX "-") == attr_id) {
        search->last = crm_int_helper(value, NULL);

    } else if (strstr(attr_id, CRM_FAIL_COUNT_PREFIX "-") == attr_id) {
        search->count += char2score(value);
    }
}

int
get_failcount(node_t *node, resource_t *rsc, time_t *last_failure,
              pe_working_set_t *data_set)
{
    return get_failcount_full(node, rsc, last_failure, TRUE, NULL, data_set);
}

static gboolean
is_matched_failure(const char *rsc_id, xmlNode *conf_op_xml,
                   xmlNode *lrm_op_xml)
{
    gboolean matched = FALSE;
    const char *conf_op_name = NULL;
    int conf_op_interval = 0;
    const char *lrm_op_task = NULL;
    int lrm_op_interval = 0;
    const char *lrm_op_id = NULL;
    char *last_failure_key = NULL;

    if (rsc_id == NULL || conf_op_xml == NULL || lrm_op_xml == NULL) {
        return FALSE;
    }

    conf_op_name = crm_element_value(conf_op_xml, "name");
    conf_op_interval = crm_get_msec(crm_element_value(conf_op_xml, "interval"));
    lrm_op_task = crm_element_value(lrm_op_xml, XML_LRM_ATTR_TASK);
    crm_element_value_int(lrm_op_xml, XML_LRM_ATTR_INTERVAL, &lrm_op_interval);

    if (safe_str_eq(conf_op_name, lrm_op_task) == FALSE
        || conf_op_interval != lrm_op_interval) {
        return FALSE;
    }

    lrm_op_id = ID(lrm_op_xml);
    last_failure_key = generate_op_key(rsc_id, "last_failure", 0);

    if (safe_str_eq(last_failure_key, lrm_op_id)) {
        matched = TRUE;

    } else {
        char *expected_op_key = generate_op_key(rsc_id, conf_op_name,
                                                conf_op_interval);

        if (safe_str_eq(expected_op_key, lrm_op_id)) {
            int rc = 0;
            int target_rc = get_target_rc(lrm_op_xml);

            crm_element_value_int(lrm_op_xml, XML_LRM_ATTR_RC, &rc);
            if (rc != target_rc) {
                matched = TRUE;
            }
        }
        free(expected_op_key);
    }

    free(last_failure_key);
    return matched;
}

static gboolean
block_failure(node_t *node, resource_t *rsc, xmlNode *xml_op,
              pe_working_set_t *data_set)
{
    char *xml_name = clone_strip(rsc->id);
    char *xpath = crm_strdup_printf("//primitive[@id='%s']//op[@on-fail='block']",
                                    xml_name);
    xmlXPathObject *xpathObj = xpath_search(rsc->xml, xpath);
    gboolean should_block = FALSE;

    free(xpath);

    if (xpathObj) {
        int max = numXpathResults(xpathObj);
        int lpc = 0;

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *pref = getXpathResult(xpathObj, lpc);

            if (xml_op) {
                should_block = is_matched_failure(xml_name, pref, xml_op);
                if (should_block) {
                    break;
                }

            } else {
                const char *conf_op_name = NULL;
                int conf_op_interval = 0;
                char *lrm_op_xpath = NULL;
                xmlXPathObject *lrm_op_xpathObj = NULL;

                conf_op_name = crm_element_value(pref, "name");
                conf_op_interval = crm_get_msec(crm_element_value(pref, "interval"));

                lrm_op_xpath = crm_strdup_printf("//node_state[@uname='%s']"
                                               "//lrm_resource[@id='%s']"
                                               "/lrm_rsc_op[@operation='%s'][@interval='%d']",
                                               node->details->uname, xml_name,
                                               conf_op_name, conf_op_interval);
                lrm_op_xpathObj = xpath_search(data_set->input, lrm_op_xpath);

                free(lrm_op_xpath);

                if (lrm_op_xpathObj) {
                    int max2 = numXpathResults(lrm_op_xpathObj);
                    int lpc2 = 0;

                    for (lpc2 = 0; lpc2 < max2; lpc2++) {
                        xmlNode *lrm_op_xml = getXpathResult(lrm_op_xpathObj,
                                                             lpc2);

                        should_block = is_matched_failure(xml_name, pref,
                                                          lrm_op_xml);
                        if (should_block) {
                            break;
                        }
                    }
                }
                freeXpathObject(lrm_op_xpathObj);

                if (should_block) {
                    break;
                }
            }
        }
    }

    free(xml_name);
    freeXpathObject(xpathObj);

    return should_block;
}

int
get_failcount_full(node_t *node, resource_t *rsc, time_t *last_failure,
                   bool effective, xmlNode *xml_op, pe_working_set_t *data_set)
{
    char *key = NULL;
    const char *value = NULL;
    struct fail_search search = { rsc, data_set, 0, 0, NULL };

    /* Optimize the "normal" case */
    key = crm_failcount_name(rsc->clone_name? rsc->clone_name : rsc->id);
    value = g_hash_table_lookup(node->details->attrs, key);
    search.count = char2score(value);
    crm_trace("%s = %s", key, value);
    free(key);

    if (value) {
        key = crm_lastfailure_name(rsc->clone_name? rsc->clone_name : rsc->id);
        value = g_hash_table_lookup(node->details->attrs, key);
        search.last = crm_int_helper(value, NULL);
        free(key);

        /* This block is still relevant once we omit anonymous instance numbers
         * because stopped clones won't have clone_name set
         */
    } else if (is_not_set(rsc->flags, pe_rsc_unique)) {
        search.rsc = uber_parent(rsc);
        search.key = clone_strip(rsc->id);

        g_hash_table_foreach(node->details->attrs, get_failcount_by_prefix,
                             &search);
        free(search.key);
        search.key = NULL;
    }

    if (search.count != 0 && search.last != 0 && last_failure) {
        *last_failure = search.last;
    }

    if (search.count && rsc->failure_timeout) {
        /* Never time-out if blocking failures are configured */
        if (block_failure(node, rsc, xml_op, data_set)) {
            pe_warn("Setting %s.failure-timeout=%d conflicts with on-fail=block: ignoring timeout",
                    rsc->id, rsc->failure_timeout);
            rsc->failure_timeout = 0;
#if 0
            /* A good idea? */
        } else if (rsc->container == NULL && is_not_set(data_set->flags, pe_flag_stonith_enabled)) {
            /* In this case, stop.on-fail defaults to block in unpack_operation() */
            rsc->failure_timeout = 0;
#endif
        }
    }

    if (effective && (search.count != 0) && (search.last != 0)
        && rsc->failure_timeout) {

        if (search.last > 0) {
            time_t now = get_effective_time(data_set);

            if (now > (search.last + rsc->failure_timeout)) {
                crm_debug("Failcount for %s on %s has expired (limit was %ds)",
                          search.rsc->id, node->details->uname,
                          rsc->failure_timeout);
                search.count = 0;
            }
        }
    }

    if (search.count != 0) {
        char *score = score2char(search.count);

        crm_info("%s has failed %s times on %s",
                 search.rsc->id, score, node->details->uname);
        free(score);
    }

    return search.count;
}

/* If it's a resource container, get its failcount plus all the failcounts of
 * the resources within it
 */
int
get_failcount_all(node_t *node, resource_t *rsc, time_t *last_failure,
                  pe_working_set_t *data_set)
{
    int failcount_all = 0;

    failcount_all = get_failcount(node, rsc, last_failure, data_set);

    if (rsc->fillers) {
        GListPtr gIter = NULL;

        for (gIter = rsc->fillers; gIter != NULL; gIter = gIter->next) {
            resource_t *filler = (resource_t *) gIter->data;
            time_t filler_last_failure = 0;

            failcount_all += get_failcount(node, filler, &filler_last_failure,
                                           data_set);

            if (last_failure && filler_last_failure > *last_failure) {
                *last_failure = filler_last_failure;
            }
        }

        if (failcount_all != 0) {
            char *score = score2char(failcount_all);

            crm_info("Container %s and the resources within it have failed %s times on %s",
                     rsc->id, score, node->details->uname);
            free(score);
        }
    }

    return failcount_all;
}
