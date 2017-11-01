/*
 * Copyright (C) 2008-2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/types.h>
#include <regex.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/pengine/internal.h>

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

#if 0
    /* A good idea? */
    if (rsc->container == NULL && is_not_set(data_set->flags, pe_flag_stonith_enabled)) {
        /* In this case, stop on-fail defaults to block in unpack_operation() */
        return TRUE;
    }
#endif

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

/*!
 * \internal
 * \brief Get resource name as used in failure-related node attributes
 *
 * \param[in] rsc  Resource to check
 *
 * \return Newly allocated string containing resource's fail name
 * \note The caller is responsible for freeing the result.
 */
static inline char *
rsc_fail_name(resource_t *rsc)
{
    const char *name = (rsc->clone_name? rsc->clone_name : rsc->id);

    return is_set(rsc->flags, pe_rsc_unique)? strdup(name) : clone_strip(name);
}

/*!
 * \internal
 * \brief Compile regular expression to match a failure-related node attribute
 *
 * \param[in]  prefix    Attribute prefix to match
 * \param[in]  rsc_name  Resource name to match as used in failure attributes
 * \param[in]  is_legacy Whether DC uses per-resource fail counts
 * \param[in]  is_unique Whether the resource is a globally unique clone
 * \param[out] re        Where to store resulting regular expression
 *
 * \note Fail attributes are named like PREFIX-RESOURCE#OP_INTERVAL.
 *       The caller is responsible for freeing re with regfree().
 */
static void
generate_fail_regex(const char *prefix, const char *rsc_name,
                    gboolean is_legacy, gboolean is_unique, regex_t *re)
{
    char *pattern;

    /* @COMPAT DC < 1.1.17: Fail counts used to be per-resource rather than
     * per-operation.
     */
    const char *op_pattern = (is_legacy? "" : "#.+_[0-9]+");

    /* Ignore instance numbers for anything other than globally unique clones.
     * Anonymous clone fail counts could contain an instance number if the
     * clone was initially unique, failed, then was converted to anonymous.
     * @COMPAT Also, before 1.1.8, anonymous clone fail counts always contained
     * clone instance numbers.
     */
    const char *instance_pattern = (is_unique? "" : "(:[0-9]+)?");

    pattern = crm_strdup_printf("^%s-%s%s%s$", prefix, rsc_name,
                                instance_pattern, op_pattern);
    CRM_LOG_ASSERT(regcomp(re, pattern, REG_EXTENDED|REG_NOSUB) == 0);
    free(pattern);
}

/*!
 * \internal
 * \brief Compile regular expressions to match failure-related node attributes
 *
 * \param[in]  rsc             Resource being checked for failures
 * \param[in]  data_set        Data set (for CRM feature set version)
 * \param[out] failcount_re    Storage for regular expression for fail count
 * \param[out] lastfailure_re  Storage for regular expression for last failure
 *
 * \note The caller is responsible for freeing the expressions with regfree().
 */
static void
generate_fail_regexes(resource_t *rsc, pe_working_set_t *data_set,
                      regex_t *failcount_re, regex_t *lastfailure_re)
{
    char *rsc_name = rsc_fail_name(rsc);
    const char *version = crm_element_value(data_set->input, XML_ATTR_CRM_VERSION);
    gboolean is_legacy = (compare_version(version, "3.0.13") < 0);

    generate_fail_regex(CRM_FAIL_COUNT_PREFIX, rsc_name, is_legacy,
                        is_set(rsc->flags, pe_rsc_unique), failcount_re);

    generate_fail_regex(CRM_LAST_FAILURE_PREFIX, rsc_name, is_legacy,
                        is_set(rsc->flags, pe_rsc_unique), lastfailure_re);

    free(rsc_name);
}

int
pe_get_failcount(node_t *node, resource_t *rsc, time_t *last_failure,
                 bool effective, xmlNode *xml_op, pe_working_set_t *data_set)
{
    char *key = NULL;
    const char *value = NULL;
    regex_t failcount_re, lastfailure_re;
    int failcount = 0;
    time_t last = 0;
    GHashTableIter iter;

    generate_fail_regexes(rsc, data_set, &failcount_re, &lastfailure_re);

    /* Resource fail count is sum of all matching operation fail counts */
    g_hash_table_iter_init(&iter, node->details->attrs);
    while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &value)) {
        if (regexec(&failcount_re, key, 0, NULL, 0) == 0) {
            failcount = merge_weights(failcount, char2score(value));
        } else if (regexec(&lastfailure_re, key, 0, NULL, 0) == 0) {
            last = QB_MAX(last, crm_int_helper(value, NULL));
        }
    }

    regfree(&failcount_re);
    regfree(&lastfailure_re);

    if ((failcount > 0) && (last > 0) && (last_failure != NULL)) {
        *last_failure = last;
    }

    /* If failure blocks the resource, disregard any failure timeout */
    if ((failcount > 0) && rsc->failure_timeout
        && block_failure(node, rsc, xml_op, data_set)) {

        pe_warn("Ignoring failure timeout %d for %s because it conflicts with on-fail=block",
                rsc->id, rsc->failure_timeout);
        rsc->failure_timeout = 0;
    }

    /* If all failures have expired, ignore fail count */
    if (effective && (failcount > 0) && (last > 0) && rsc->failure_timeout) {
        time_t now = get_effective_time(data_set);

        if (now > (last + rsc->failure_timeout)) {
            crm_debug("Failcount for %s on %s expired after %ds",
                      rsc->id, node->details->uname, rsc->failure_timeout);
            failcount = 0;
        }
    }

    if (failcount > 0) {
        char *score = score2char(failcount);

        crm_info("%s has failed %s times on %s",
                 rsc->id, score, node->details->uname);
        free(score);
    }

    return failcount;
}

/* If it's a resource container, get its failcount plus all the failcounts of
 * the resources within it
 */
int
get_failcount_all(node_t *node, resource_t *rsc, time_t *last_failure,
                  pe_working_set_t *data_set)
{
    int failcount_all = 0;

    failcount_all = pe_get_failcount(node, rsc, last_failure, TRUE, NULL, data_set);

    if (rsc->fillers) {
        GListPtr gIter = NULL;

        for (gIter = rsc->fillers; gIter != NULL; gIter = gIter->next) {
            resource_t *filler = (resource_t *) gIter->data;
            time_t filler_last_failure = 0;

            failcount_all += pe_get_failcount(node, filler, &filler_last_failure,
                                              TRUE, NULL, data_set);

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
