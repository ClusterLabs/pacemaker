/*
 * Copyright 2008-2024 the Pacemaker project contributors
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/types.h>
#include <regex.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/pengine/internal.h>

static gboolean
is_matched_failure(const char *rsc_id, const xmlNode *conf_op_xml,
                   const xmlNode *lrm_op_xml)
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
    conf_op_name = crm_element_value(conf_op_xml, PCMK_XA_NAME);
    conf_op_interval_spec = crm_element_value(conf_op_xml, PCMK_META_INTERVAL);
    pcmk_parse_interval_spec(conf_op_interval_spec, &conf_op_interval_ms);

    // Get name and interval from op history entry
    lrm_op_task = crm_element_value(lrm_op_xml, PCMK_XA_OPERATION);
    crm_element_value_ms(lrm_op_xml, PCMK_META_INTERVAL, &lrm_op_interval_ms);

    if ((conf_op_interval_ms != lrm_op_interval_ms)
        || !pcmk__str_eq(conf_op_name, lrm_op_task, pcmk__str_casei)) {
        return FALSE;
    }

    lrm_op_id = pcmk__xe_id(lrm_op_xml);
    last_failure_key = pcmk__op_key(rsc_id, "last_failure", 0);

    if (pcmk__str_eq(last_failure_key, lrm_op_id, pcmk__str_casei)) {
        matched = TRUE;

    } else {
        char *expected_op_key = pcmk__op_key(rsc_id, conf_op_name,
                                                conf_op_interval_ms);

        if (pcmk__str_eq(expected_op_key, lrm_op_id, pcmk__str_casei)) {
            int rc = 0;
            int target_rc = pe__target_rc_from_xml(lrm_op_xml);

            crm_element_value_int(lrm_op_xml, PCMK__XA_RC_CODE, &rc);
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
block_failure(const pcmk_node_t *node, pcmk_resource_t *rsc,
              const xmlNode *xml_op)
{
    char *xml_name = clone_strip(rsc->id);

    /* @TODO This xpath search occurs after template expansion, but it is unable
     * to properly detect on-fail in id-ref, operation meta-attributes, or
     * op_defaults, or evaluate rules.
     *
     * Also, PCMK_META_ON_FAIL defaults to PCMK_VALUE_BLOCK (in
     * unpack_operation()) for stop actions when stonith is disabled.
     *
     * Ideally, we'd unpack the operation before this point, and pass in a
     * meta-attributes table that takes all that into consideration.
     */
    char *xpath = crm_strdup_printf("//" PCMK_XE_PRIMITIVE
                                    "[@" PCMK_XA_ID "='%s']"
                                    "//" PCMK_XE_OP
                                    "[@" PCMK_META_ON_FAIL
                                        "='" PCMK_VALUE_BLOCK "']",
                                    xml_name);

    xmlXPathObject *xpathObj = xpath_search(rsc->private->xml, xpath);
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
                conf_op_name = crm_element_value(pref, PCMK_XA_NAME);
                conf_op_interval_spec = crm_element_value(pref,
                                                          PCMK_META_INTERVAL);
                pcmk_parse_interval_spec(conf_op_interval_spec,
                                         &conf_op_interval_ms);

#define XPATH_FMT "//" PCMK__XE_NODE_STATE "[@" PCMK_XA_UNAME "='%s']"      \
                  "//" PCMK__XE_LRM_RESOURCE "[@" PCMK_XA_ID "='%s']"       \
                  "/" PCMK__XE_LRM_RSC_OP "[@" PCMK_XA_OPERATION "='%s']"   \
                  "[@" PCMK_META_INTERVAL "='%u']"

                lrm_op_xpath = crm_strdup_printf(XPATH_FMT,
                                                 node->details->uname, xml_name,
                                                 conf_op_name,
                                                 conf_op_interval_ms);
                lrm_op_xpathObj = xpath_search(rsc->private->scheduler->input,
                                               lrm_op_xpath);

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
rsc_fail_name(const pcmk_resource_t *rsc)
{
    const char *name = pcmk__s(rsc->private->history_id, rsc->id);

    return pcmk_is_set(rsc->flags, pcmk_rsc_unique)? strdup(name) : clone_strip(name);
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
 * \param[out] failcount_re    Storage for regular expression for fail count
 * \param[out] lastfailure_re  Storage for regular expression for last failure
 *
 * \return Standard Pacemaker return code
 * \note On success, the caller is responsible for freeing the expressions with
 *       regfree().
 */
static int
generate_fail_regexes(const pcmk_resource_t *rsc,
                      regex_t *failcount_re, regex_t *lastfailure_re)
{
    int rc = pcmk_rc_ok;
    char *rsc_name = rsc_fail_name(rsc);
    const char *version = crm_element_value(rsc->private->scheduler->input,
                                            PCMK_XA_CRM_FEATURE_SET);

    // @COMPAT Pacemaker <= 1.1.16 used a single fail count per resource
    gboolean is_legacy = (compare_version(version, "3.0.13") < 0);

    if (generate_fail_regex(PCMK__FAIL_COUNT_PREFIX, rsc_name, is_legacy,
                            pcmk_is_set(rsc->flags, pcmk_rsc_unique),
                            failcount_re) != pcmk_rc_ok) {
        rc = EINVAL;

    } else if (generate_fail_regex(PCMK__LAST_FAILURE_PREFIX, rsc_name,
                                   is_legacy,
                                   pcmk_is_set(rsc->flags, pcmk_rsc_unique),
                                   lastfailure_re) != pcmk_rc_ok) {
        rc = EINVAL;
        regfree(failcount_re);
    }

    free(rsc_name);
    return rc;
}

// Data for fail-count-related iterators
struct failcount_data {
    const pcmk_node_t *node;// Node to check for fail count
    pcmk_resource_t *rsc;     // Resource to check for fail count
    uint32_t flags;         // Fail count flags
    const xmlNode *xml_op;  // History entry for expiration purposes (or NULL)
    regex_t failcount_re;   // Fail count regular expression to match
    regex_t lastfailure_re; // Last failure regular expression to match
    int failcount;          // Fail count so far
    time_t last_failure;    // Time of most recent failure so far
};

/*!
 * \internal
 * \brief Update fail count and last failure appropriately for a node attribute
 *
 * \param[in] key        Node attribute name
 * \param[in] value      Node attribute value
 * \param[in] user_data  Fail count data to update
 */
static void
update_failcount_for_attr(gpointer key, gpointer value, gpointer user_data)
{
    struct failcount_data *fc_data = user_data;

    // If this is a matching fail count attribute, update fail count
    if (regexec(&(fc_data->failcount_re), (const char *) key, 0, NULL, 0) == 0) {
        fc_data->failcount = pcmk__add_scores(fc_data->failcount,
                                              char2score(value));
        pcmk__rsc_trace(fc_data->rsc, "Added %s (%s) to %s fail count (now %s)",
                        (const char *) key, (const char *) value,
                        fc_data->rsc->id,
                        pcmk_readable_score(fc_data->failcount));
        return;
    }

    // If this is a matching last failure attribute, update last failure
    if (regexec(&(fc_data->lastfailure_re), (const char *) key, 0, NULL,
                0) == 0) {
        long long last_ll;

        if (pcmk__scan_ll(value, &last_ll, 0LL) == pcmk_rc_ok) {
            fc_data->last_failure = (time_t) QB_MAX(fc_data->last_failure,
                                                    last_ll);
        }
    }
}

/*!
 * \internal
 * \brief Update fail count and last failure appropriately for a filler resource
 *
 * \param[in] data       Filler resource
 * \param[in] user_data  Fail count data to update
 */
static void
update_failcount_for_filler(gpointer data, gpointer user_data)
{
    pcmk_resource_t *filler = data;
    struct failcount_data *fc_data = user_data;
    time_t filler_last_failure = 0;

    fc_data->failcount += pe_get_failcount(fc_data->node, filler,
                                           &filler_last_failure, fc_data->flags,
                                           fc_data->xml_op);
    fc_data->last_failure = QB_MAX(fc_data->last_failure, filler_last_failure);
}

/*!
 * \internal
 * \brief Get a resource's fail count on a node
 *
 * \param[in]     node          Node to check
 * \param[in,out] rsc           Resource to check
 * \param[out]    last_failure  If not NULL, where to set time of most recent
 *                              failure of \p rsc on \p node
 * \param[in]     flags         Group of enum pcmk__fc_flags
 * \param[in]     xml_op        If not NULL, consider only the action in this
 *                              history entry when determining whether on-fail
 *                              is configured as "blocked", otherwise consider
 *                              all actions configured for \p rsc
 *
 * \return Fail count for \p rsc on \p node according to \p flags
 */
int
pe_get_failcount(const pcmk_node_t *node, pcmk_resource_t *rsc,
                 time_t *last_failure, uint32_t flags, const xmlNode *xml_op)
{
    struct failcount_data fc_data = {
        .node = node,
        .rsc = rsc,
        .flags = flags,
        .xml_op = xml_op,
        .failcount = 0,
        .last_failure = (time_t) 0,
    };

    // Calculate resource failcount as sum of all matching operation failcounts
    CRM_CHECK(generate_fail_regexes(rsc, &fc_data.failcount_re,
                                    &fc_data.lastfailure_re) == pcmk_rc_ok,
              return 0);
    g_hash_table_foreach(node->details->attrs, update_failcount_for_attr,
                         &fc_data);
    regfree(&(fc_data.failcount_re));
    regfree(&(fc_data.lastfailure_re));

    // If failure blocks the resource, disregard any failure timeout
    if ((fc_data.failcount > 0) && (rsc->failure_timeout > 0)
        && block_failure(node, rsc, xml_op)) {

        pcmk__config_warn("Ignoring failure timeout %d for %s "
                          "because it conflicts with "
                          PCMK_META_ON_FAIL "=" PCMK_VALUE_BLOCK,
                          rsc->failure_timeout, rsc->id);
        rsc->failure_timeout = 0;
    }

    // If all failures have expired, ignore fail count
    if (pcmk_is_set(flags, pcmk__fc_effective) && (fc_data.failcount > 0)
        && (fc_data.last_failure > 0) && (rsc->failure_timeout != 0)) {

        time_t now = get_effective_time(rsc->private->scheduler);

        if (now > (fc_data.last_failure + rsc->failure_timeout)) {
            pcmk__rsc_debug(rsc, "Failcount for %s on %s expired after %ds",
                            rsc->id, pcmk__node_name(node),
                            rsc->failure_timeout);
            fc_data.failcount = 0;
        }
    }

    /* Add the fail count of any filler resources, except that we never want the
     * fail counts of a bundle container's fillers to count towards the
     * container's fail count.
     *
     * Most importantly, a Pacemaker Remote connection to a bundle container
     * is a filler of the container, but can reside on a different node than the
     * container itself. Counting its fail count on its node towards the
     * container's fail count on that node could lead to attempting to stop the
     * container on the wrong node.
     */
    if (pcmk_is_set(flags, pcmk__fc_fillers) && (rsc->fillers != NULL)
        && !pcmk__is_bundled(rsc)) {

        g_list_foreach(rsc->fillers, update_failcount_for_filler, &fc_data);
        if (fc_data.failcount > 0) {
            pcmk__rsc_info(rsc,
                           "Container %s and the resources within it "
                           "have failed %s time%s on %s",
                           rsc->id, pcmk_readable_score(fc_data.failcount),
                           pcmk__plural_s(fc_data.failcount),
                           pcmk__node_name(node));
        }

    } else if (fc_data.failcount > 0) {
        pcmk__rsc_info(rsc, "%s has failed %s time%s on %s",
                       rsc->id, pcmk_readable_score(fc_data.failcount),
                       pcmk__plural_s(fc_data.failcount),
                       pcmk__node_name(node));
    }

    if (last_failure != NULL) {
        if ((fc_data.failcount > 0) && (fc_data.last_failure > 0)) {
            *last_failure = fc_data.last_failure;
        } else  {
            *last_failure = 0;
        }
    }
    return fc_data.failcount;
}

/*!
 * \brief Schedule a controller operation to clear a fail count
 *
 * \param[in,out] rsc        Resource with failure
 * \param[in]     node       Node failure occurred on
 * \param[in]     reason     Readable description why needed (for logging)
 * \param[in,out] scheduler  Scheduler data cluster
 *
 * \return Scheduled action
 */
pcmk_action_t *
pe__clear_failcount(pcmk_resource_t *rsc, const pcmk_node_t *node,
                    const char *reason, pcmk_scheduler_t *scheduler)
{
    char *key = NULL;
    pcmk_action_t *clear = NULL;

    CRM_CHECK(rsc && node && reason && scheduler, return NULL);

    key = pcmk__op_key(rsc->id, PCMK_ACTION_CLEAR_FAILCOUNT, 0);
    clear = custom_action(rsc, key, PCMK_ACTION_CLEAR_FAILCOUNT, node, FALSE,
                          scheduler);
    pcmk__insert_meta(clear, PCMK__META_OP_NO_WAIT, PCMK_VALUE_TRUE);
    crm_notice("Clearing failure of %s on %s because %s " CRM_XS " %s",
               rsc->id, pcmk__node_name(node), reason, clear->uuid);
    return clear;
}
