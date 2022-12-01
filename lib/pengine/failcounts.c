/*
 * Copyright 2008-2022 the Pacemaker project contributors
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
    const char *lrm_op_task = NULL;
    const char *conf_op_interval_spec = NULL;
    guint conf_op_interval_ms = 0;
    guint lrm_op_interval_ms = 0;
    const char *lrm_op_id = NULL;
    char *last_failure_key = NULL;

    if (rsc_id == NULL || conf_op_xml == NULL || lrm_op_xml == NULL) {
        return FALSE;
    }

    // Get name and interval from configured op
    conf_op_name = crm_element_value(conf_op_xml, "name");
    conf_op_interval_spec = crm_element_value(conf_op_xml,
                                              XML_LRM_ATTR_INTERVAL);
    conf_op_interval_ms = crm_parse_interval_spec(conf_op_interval_spec);

    // Get name and interval from op history entry
    lrm_op_task = crm_element_value(lrm_op_xml, XML_LRM_ATTR_TASK);
    crm_element_value_ms(lrm_op_xml, XML_LRM_ATTR_INTERVAL_MS,
                         &lrm_op_interval_ms);

    if ((conf_op_interval_ms != lrm_op_interval_ms)
        || !pcmk__str_eq(conf_op_name, lrm_op_task, pcmk__str_casei)) {
        return FALSE;
    }

    lrm_op_id = ID(lrm_op_xml);
    last_failure_key = pcmk__op_key(rsc_id, "last_failure", 0);

    if (pcmk__str_eq(last_failure_key, lrm_op_id, pcmk__str_casei)) {
        matched = TRUE;

    } else {
        char *expected_op_key = pcmk__op_key(rsc_id, conf_op_name,
                                                conf_op_interval_ms);

        if (pcmk__str_eq(expected_op_key, lrm_op_id, pcmk__str_casei)) {
            int rc = 0;
            int target_rc = pe__target_rc_from_xml(lrm_op_xml);

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
block_failure(pe_node_t *node, pe_resource_t *rsc, xmlNode *xml_op,
              pe_working_set_t *data_set)
{
    char *xml_name = clone_strip(rsc->id);

    /* @TODO This xpath search occurs after template expansion, but it is unable
     * to properly detect on-fail in id-ref, operation meta-attributes, or
     * op_defaults, or evaluate rules.
     *
     * Also, on-fail defaults to block (in unpack_operation()) for stop actions
     * when stonith is disabled.
     *
     * Ideally, we'd unpack the operation before this point, and pass in a
     * meta-attributes table that takes all that into consideration.
     */
    char *xpath = crm_strdup_printf("//" XML_CIB_TAG_RESOURCE
                                    "[@" XML_ATTR_ID "='%s']"
                                    "//" XML_ATTR_OP
                                    "[@" XML_OP_ATTR_ON_FAIL "='block']",
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
                const char *conf_op_interval_spec = NULL;
                guint conf_op_interval_ms = 0;
                char *lrm_op_xpath = NULL;
                xmlXPathObject *lrm_op_xpathObj = NULL;

                // Get name and interval from configured op
                conf_op_name = crm_element_value(pref, "name");
                conf_op_interval_spec = crm_element_value(pref, XML_LRM_ATTR_INTERVAL);
                conf_op_interval_ms = crm_parse_interval_spec(conf_op_interval_spec);

#define XPATH_FMT "//" XML_CIB_TAG_STATE "[@" XML_ATTR_UNAME "='%s']"       \
                  "//" XML_LRM_TAG_RESOURCE "[@" XML_ATTR_ID "='%s']"       \
                  "/" XML_LRM_TAG_RSC_OP "[@" XML_LRM_ATTR_TASK "='%s']"    \
                  "[@" XML_LRM_ATTR_INTERVAL "='%u']"

                lrm_op_xpath = crm_strdup_printf(XPATH_FMT,
                                                 node->details->uname, xml_name,
                                                 conf_op_name,
                                                 conf_op_interval_ms);
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
rsc_fail_name(pe_resource_t *rsc)
{
    const char *name = (rsc->clone_name? rsc->clone_name : rsc->id);

    return pcmk_is_set(rsc->flags, pe_rsc_unique)? strdup(name) : clone_strip(name);
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
 * \return Standard Pacemaker return code
 * \note Fail attributes are named like PREFIX-RESOURCE#OP_INTERVAL.
 *       The caller is responsible for freeing re with regfree().
 */
static int
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
    if (regcomp(re, pattern, REG_EXTENDED|REG_NOSUB) != 0) {
        free(pattern);
        return EINVAL;
    }

    free(pattern);
    return pcmk_rc_ok;
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
 * \return Standard Pacemaker return code
 * \note On success, the caller is responsible for freeing the expressions with
 *       regfree().
 */
static int
generate_fail_regexes(pe_resource_t *rsc, pe_working_set_t *data_set,
                      regex_t *failcount_re, regex_t *lastfailure_re)
{
    char *rsc_name = rsc_fail_name(rsc);
    const char *version = crm_element_value(data_set->input, XML_ATTR_CRM_VERSION);
    gboolean is_legacy = (compare_version(version, "3.0.13") < 0);
    int rc = pcmk_rc_ok;

    if (generate_fail_regex(PCMK__FAIL_COUNT_PREFIX, rsc_name, is_legacy,
                            pcmk_is_set(rsc->flags, pe_rsc_unique),
                            failcount_re) != pcmk_rc_ok) {
        rc = EINVAL;

    } else if (generate_fail_regex(PCMK__LAST_FAILURE_PREFIX, rsc_name,
                                   is_legacy,
                                   pcmk_is_set(rsc->flags, pe_rsc_unique),
                                   lastfailure_re) != pcmk_rc_ok) {
        rc = EINVAL;
        regfree(failcount_re);
    }

    free(rsc_name);
    return rc;
}

int
pe_get_failcount(pe_node_t *node, pe_resource_t *rsc, time_t *last_failure,
                 uint32_t flags, xmlNode *xml_op, pe_working_set_t *data_set)
{
    char *key = NULL;
    const char *value = NULL;
    regex_t failcount_re, lastfailure_re;
    int failcount = 0;
    time_t last = 0;
    GHashTableIter iter;

    CRM_CHECK(generate_fail_regexes(rsc, data_set, &failcount_re,
                                    &lastfailure_re) == pcmk_rc_ok,
              return 0);

    /* Resource fail count is sum of all matching operation fail counts */
    g_hash_table_iter_init(&iter, node->details->attrs);
    while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &value)) {
        if (regexec(&failcount_re, key, 0, NULL, 0) == 0) {
            failcount = pcmk__add_scores(failcount, char2score(value));
        } else if (regexec(&lastfailure_re, key, 0, NULL, 0) == 0) {
            long long last_ll;

            if (pcmk__scan_ll(value, &last_ll, 0LL) == pcmk_rc_ok) {
                last = (time_t) QB_MAX(last, last_ll);
            }
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
                rsc->failure_timeout, rsc->id);
        rsc->failure_timeout = 0;
    }

    /* If all failures have expired, ignore fail count */
    if (pcmk_is_set(flags, pe_fc_effective) && (failcount > 0) && (last > 0)
        && rsc->failure_timeout) {

        time_t now = get_effective_time(data_set);

        if (now > (last + rsc->failure_timeout)) {
            crm_debug("Failcount for %s on %s expired after %ds",
                      rsc->id, pe__node_name(node), rsc->failure_timeout);
            failcount = 0;
        }
    }

    /* We never want the fail counts of a bundle container's fillers to
     * count towards the container's fail count.
     *
     * Most importantly, a Pacemaker Remote connection to a bundle container
     * is a filler of the container, but can reside on a different node than the
     * container itself. Counting its fail count on its node towards the
     * container's fail count on that node could lead to attempting to stop the
     * container on the wrong node.
     */

    if (pcmk_is_set(flags, pe_fc_fillers) && rsc->fillers
        && !pe_rsc_is_bundled(rsc)) {

        GList *gIter = NULL;

        for (gIter = rsc->fillers; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *filler = (pe_resource_t *) gIter->data;
            time_t filler_last_failure = 0;

            failcount += pe_get_failcount(node, filler, &filler_last_failure,
                                          flags, xml_op, data_set);

            if (last_failure && filler_last_failure > *last_failure) {
                *last_failure = filler_last_failure;
            }
        }

        if (failcount > 0) {
            crm_info("Container %s and the resources within it "
                     "have failed %s time%s on %s",
                     rsc->id, pcmk_readable_score(failcount),
                     pcmk__plural_s(failcount), pe__node_name(node));
        }

    } else if (failcount > 0) {
        crm_info("%s has failed %s time%s on %s",
                 rsc->id, pcmk_readable_score(failcount),
                 pcmk__plural_s(failcount), pe__node_name(node));
    }

    return failcount;
}

/*!
 * \brief Schedule a controller operation to clear a fail count
 *
 * \param[in] rsc       Resource with failure
 * \param[in] node      Node failure occurred on
 * \param[in] reason    Readable description why needed (for logging)
 * \param[in] data_set  Working set for cluster
 *
 * \return Scheduled action
 */
pe_action_t *
pe__clear_failcount(pe_resource_t *rsc, pe_node_t *node,
                    const char *reason, pe_working_set_t *data_set)
{
    char *key = NULL;
    pe_action_t *clear = NULL;

    CRM_CHECK(rsc && node && reason && data_set, return NULL);

    key = pcmk__op_key(rsc->id, CRM_OP_CLEAR_FAILCOUNT, 0);
    clear = custom_action(rsc, key, CRM_OP_CLEAR_FAILCOUNT, node, FALSE, TRUE,
                          data_set);
    add_hash_param(clear->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
    crm_notice("Clearing failure of %s on %s because %s " CRM_XS " %s",
               rsc->id, pe__node_name(node), reason, clear->uuid);
    return clear;
}
