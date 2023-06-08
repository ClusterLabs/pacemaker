/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>                          // NULL, size_t
#include <stdbool.h>                        // bool
#include <ctype.h>                          // isdigit()
#include <regex.h>                          // regmatch_t
#include <stdint.h>                         // uint32_t
#include <inttypes.h>                       // PRIu32
#include <glib.h>                           // gboolean, FALSE
#include <libxml/tree.h>                    // xmlNode

#include <crm/common/scheduler.h>

#include <crm/common/iso8601_internal.h>
#include <crm/common/nvpair_internal.h>
#include <crm/common/scheduler_internal.h>
#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Get the expression type corresponding to given expression XML
 *
 * \param[in] expr  Rule expression XML
 *
 * \return Expression type corresponding to \p expr
 */
enum expression_type
pcmk__expression_type(const xmlNode *expr)
{
    const char *name = NULL;

    // Expression types based on element name

    if (pcmk__xe_is(expr, PCMK_XE_DATE_EXPRESSION)) {
        return pcmk__subexpr_datetime;

    } else if (pcmk__xe_is(expr, PCMK_XE_RSC_EXPRESSION)) {
        return pcmk__subexpr_resource;

    } else if (pcmk__xe_is(expr, PCMK_XE_OP_EXPRESSION)) {
        return pcmk__subexpr_operation;

    } else if (pcmk__xe_is(expr, PCMK_XE_RULE)) {
        return pcmk__subexpr_rule;

    } else if (!pcmk__xe_is(expr, PCMK_XE_EXPRESSION)) {
        return pcmk__subexpr_unknown;
    }

    // Expression types based on node attribute name

    name = crm_element_value(expr, PCMK_XA_ATTRIBUTE);

    if (pcmk__str_any_of(name, CRM_ATTR_UNAME, CRM_ATTR_KIND, CRM_ATTR_ID,
                         NULL)) {
        return pcmk__subexpr_location;
    }

    return pcmk__subexpr_attribute;
}

/*!
 * \internal
 * \brief Get parent XML element's ID for logging purposes
 *
 * \param[in] xml  XML of a subelement
 *
 * \return ID of \p xml's parent for logging purposes (guaranteed non-NULL)
 */
static const char *
loggable_parent_id(const xmlNode *xml)
{
    // Default if called without parent (likely for unit testing)
    const char *parent_id = "implied";

    if ((xml != NULL) && (xml->parent != NULL)) {
        parent_id = pcmk__xe_id(xml->parent);
        if (parent_id == NULL) { // Not possible with schema validation enabled
            parent_id = "without ID";
        }
    }
    return parent_id;
}

/*!
 * \internal
 * \brief Get the moon phase corresponding to a given date/time
 *
 * \param[in] now  Date/time to get moon phase for
 *
 * \return Phase of the moon corresponding to \p now, where 0 is the new moon
 *         and 7 is the full moon
 * \deprecated This feature has been deprecated since 2.1.6.
 */
static int
phase_of_the_moon(const crm_time_t *now)
{
    /* As per the nethack rules:
     * - A moon period is 29.53058 days ~= 30
     * - A year is 365.2422 days
     * - Number of days moon phase advances on first day of year compared to
     *   preceding year is (365.2422 - 12 * 29.53058) ~= 11
     * - Number of years until same phases fall on the same days of the month
     *   is 18.6 ~= 19
     * - Moon phase on first day of year (epact) ~= (11 * (year%19) + 29) % 30
     *   (29 as initial condition)
     * - Current phase in days = first day phase + days elapsed in year
     * - 6 moons ~= 177 days ~= 8 reported phases * 22 (+ 11/22 for rounding)
     */
    uint32_t epact, diy, goldn;
    uint32_t y;

    crm_time_get_ordinal(now, &y, &diy);
    goldn = (y % 19) + 1;
    epact = (11 * goldn + 18) % 30;
    if (((epact == 25) && (goldn > 11)) || (epact == 24)) {
        epact++;
    }
    return (((((diy + epact) * 6) + 11) % 177) / 22) & 7;
}

/*!
 * \internal
 * \brief Check an integer value against a range from a date specification
 *
 * \param[in] date_spec  XML of PCMK_XE_DATE_SPEC element to check
 * \param[in] id         XML ID for logging purposes
 * \param[in] attr       Name of XML attribute with range to check against
 * \param[in] value      Value to compare against range
 *
 * \return Standard Pacemaker return code (specifically, pcmk_rc_before_range,
 *         pcmk_rc_after_range, or pcmk_rc_ok to indicate that result is either
 *         within range or undetermined)
 * \note We return pcmk_rc_ok for an undetermined result so we can continue
 *       checking the next range attribute.
 */
static int
check_range(const xmlNode *date_spec, const char *id, const char *attr,
            uint32_t value)
{
    int rc = pcmk_rc_ok;
    const char *range = crm_element_value(date_spec, attr);
    long long low, high;

    if (range == NULL) { // Attribute not present
        goto bail;
    }

    if (pcmk__parse_ll_range(range, &low, &high) != pcmk_rc_ok) {
        // Invalid range
        /* @COMPAT When we can break behavioral backward compatibility, treat
         * the entire rule as not passing.
         */
        pcmk__config_err("Ignoring " PCMK_XE_DATE_SPEC
                         " %s attribute %s because '%s' is not a valid range",
                         id, attr, range);

    } else if ((low != -1) && (value < low)) {
        rc = pcmk_rc_before_range;

    } else if ((high != -1) && (value > high)) {
        rc = pcmk_rc_after_range;
    }

bail:
    crm_trace("Checked " PCMK_XE_DATE_SPEC " %s %s='%s' for %" PRIu32 ": %s",
              id, attr, pcmk__s(range, ""), value, pcmk_rc_str(rc));
    return rc;
}

/*!
 * \internal
 * \brief Evaluate a date specification for a given date/time
 *
 * \param[in] date_spec  XML of PCMK_XE_DATE_SPEC element to evaluate
 * \param[in] now        Time to check
 *
 * \return Standard Pacemaker return code (specifically, EINVAL for NULL
 *         arguments, pcmk_rc_ok if time matches specification, or
 *         pcmk_rc_before_range, pcmk_rc_after_range, or pcmk_rc_op_unsatisfied
 *         as appropriate to how time relates to specification)
 */
int
pcmk__evaluate_date_spec(const xmlNode *date_spec, const crm_time_t *now)
{
    const char *id = NULL;
    const char *parent_id = loggable_parent_id(date_spec);

    // Range attributes that can be specified for a PCMK_XE_DATE_SPEC element
    struct range {
        const char *attr;
        uint32_t value;
    } ranges[] = {
        { PCMK_XA_YEARS, 0U },
        { PCMK_XA_MONTHS, 0U },
        { PCMK_XA_MONTHDAYS, 0U },
        { PCMK_XA_HOURS, 0U },
        { PCMK_XA_MINUTES, 0U },
        { PCMK_XA_SECONDS, 0U },
        { PCMK_XA_YEARDAYS, 0U },
        { PCMK_XA_WEEKYEARS, 0U },
        { PCMK_XA_WEEKS, 0U },
        { PCMK_XA_WEEKDAYS, 0U },
        { PCMK__XA_MOON, 0U },
    };

    if ((date_spec == NULL) || (now == NULL)) {
        return EINVAL;
    }

    // Get specification ID (for logging)
    id = pcmk__xe_id(date_spec);
    if (pcmk__str_empty(id)) { // Not possible with schema validation enabled
        /* @COMPAT When we can break behavioral backward compatibility,
         * fail the specification
         */
        pcmk__config_warn(PCMK_XE_DATE_SPEC " subelement of "
                          PCMK_XE_DATE_EXPRESSION " %s has no " PCMK_XA_ID,
                          parent_id);
        id = "without ID"; // for logging
    }

    // Year, month, day
    crm_time_get_gregorian(now, &(ranges[0].value), &(ranges[1].value),
                           &(ranges[2].value));

    // Hour, minute, second
    crm_time_get_timeofday(now, &(ranges[3].value), &(ranges[4].value),
                           &(ranges[5].value));

    // Year (redundant) and day of year
    crm_time_get_ordinal(now, &(ranges[0].value), &(ranges[6].value));

    // Week year, week of week year, day of week
    crm_time_get_isoweek(now, &(ranges[7].value), &(ranges[8].value),
                         &(ranges[9].value));

    // Moon phase (deprecated)
    ranges[10].value = phase_of_the_moon(now);
    if (crm_element_value(date_spec, PCMK__XA_MOON) != NULL) {
        pcmk__config_warn("Support for '" PCMK__XA_MOON "' in "
                          PCMK_XE_DATE_SPEC " elements (such as %s) is "
                          "deprecated and will be removed in a future release "
                          "of Pacemaker", id);
    }

    for (int i = 0; i < PCMK__NELEM(ranges); ++i) {
        int rc = check_range(date_spec, id, ranges[i].attr, ranges[i].value);

        if (rc != pcmk_rc_ok) {
            return rc;
        }
    }

    // All specified ranges passed, or none were given (also considered a pass)
    return pcmk_rc_ok;
}

#define ADD_COMPONENT(component) do {                                       \
        int sub_rc = pcmk__add_time_from_xml(*end, component, duration);    \
        if (sub_rc != pcmk_rc_ok) {                                         \
            /* @COMPAT return sub_rc when we can break compatibility */     \
            pcmk__config_warn("Ignoring %s in " PCMK_XE_DURATION " %s "     \
                              "because it is invalid",                      \
                              pcmk__time_component_attr(component), id);    \
            rc = sub_rc;                                                    \
        }                                                                   \
    } while (0)

/*!
 * \internal
 * \brief Given a duration and a start time, calculate the end time
 *
 * \param[in]  duration  XML of PCMK_XE_DURATION element
 * \param[in]  start     Start time
 * \param[out] end       Where to store end time (\p *end must be NULL
 *                       initially)
 *
 * \return Standard Pacemaker return code
 * \note The caller is responsible for freeing \p *end using crm_time_free().
 */
int
pcmk__unpack_duration(const xmlNode *duration, const crm_time_t *start,
                      crm_time_t **end)
{
    int rc = pcmk_rc_ok;
    const char *id = NULL;
    const char *parent_id = loggable_parent_id(duration);

    if ((start == NULL) || (duration == NULL)
        || (end == NULL) || (*end != NULL)) {
        return EINVAL;
    }

    // Get duration ID (for logging)
    id = pcmk__xe_id(duration);
    if (pcmk__str_empty(id)) { // Not possible with schema validation enabled
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error instead
         */
        pcmk__config_warn(PCMK_XE_DURATION " subelement of "
                          PCMK_XE_DATE_EXPRESSION " %s has no " PCMK_XA_ID,
                          parent_id);
        id = "without ID";
    }

    *end = pcmk_copy_time(start);

    ADD_COMPONENT(pcmk__time_years);
    ADD_COMPONENT(pcmk__time_months);
    ADD_COMPONENT(pcmk__time_weeks);
    ADD_COMPONENT(pcmk__time_days);
    ADD_COMPONENT(pcmk__time_hours);
    ADD_COMPONENT(pcmk__time_minutes);
    ADD_COMPONENT(pcmk__time_seconds);

    return rc;
}

/*!
 * \internal
 * \brief Evaluate a range check for a given date/time
 *
 * \param[in]     date_expression  XML of PCMK_XE_DATE_EXPRESSION element
 * \param[in]     id               Expression ID for logging purposes
 * \param[in]     now              Date/time to compare
 * \param[in,out] next_change      If not NULL, set this to when the evaluation
 *                                 will change, if known and earlier than the
 *                                 original value
 *
 * \return Standard Pacemaker return code
 */
static int
evaluate_in_range(const xmlNode *date_expression, const char *id,
                  const crm_time_t *now, crm_time_t *next_change)
{
    crm_time_t *start = NULL;
    crm_time_t *end = NULL;

    if (pcmk__xe_get_datetime(date_expression, PCMK_XA_START,
                              &start) != pcmk_rc_ok) {
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error
         */
        pcmk__config_warn("Ignoring " PCMK_XA_START " in "
                          PCMK_XE_DATE_EXPRESSION " %s because it is invalid",
                          id);
    }

    if (pcmk__xe_get_datetime(date_expression, PCMK_XA_END,
                              &end) != pcmk_rc_ok) {
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error
         */
        pcmk__config_warn("Ignoring " PCMK_XA_END " in "
                          PCMK_XE_DATE_EXPRESSION " %s because it is invalid",
                          id);
    }

    if ((start == NULL) && (end == NULL)) {
        // Not possible with schema validation enabled
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error
         */
        pcmk__config_warn("Treating " PCMK_XE_DATE_EXPRESSION " %s as not "
                          "passing because in_range requires at least one of "
                          PCMK_XA_START " or " PCMK_XA_END, id);
        return pcmk_rc_undetermined;
    }

    if (end == NULL) {
        xmlNode *duration = pcmk__xe_first_child(date_expression,
                                                 PCMK_XE_DURATION, NULL, NULL);

        if (duration != NULL) {
            /* @COMPAT When we can break behavioral backward compatibility,
             * return the result of this if not OK
             */
            pcmk__unpack_duration(duration, start, &end);
        }
    }

    if ((start != NULL) && (crm_time_compare(now, start) < 0)) {
        pcmk__set_time_if_earlier(next_change, start);
        crm_time_free(start);
        crm_time_free(end);
        return pcmk_rc_before_range;
    }

    if (end != NULL) {
        if (crm_time_compare(now, end) > 0) {
            crm_time_free(start);
            crm_time_free(end);
            return pcmk_rc_after_range;
        }

        // Evaluation doesn't change until second after end
        if (next_change != NULL) {
            crm_time_add_seconds(end, 1);
            pcmk__set_time_if_earlier(next_change, end);
        }
    }

    crm_time_free(start);
    crm_time_free(end);
    return pcmk_rc_within_range;
}

/*!
 * \internal
 * \brief Evaluate a greater-than check for a given date/time
 *
 * \param[in]     date_expression  XML of PCMK_XE_DATE_EXPRESSION element
 * \param[in]     id               Expression ID for logging purposes
 * \param[in]     now              Date/time to compare
 * \param[in,out] next_change      If not NULL, set this to when the evaluation
 *                                 will change, if known and earlier than the
 *                                 original value
 *
 * \return Standard Pacemaker return code
 */
static int
evaluate_gt(const xmlNode *date_expression, const char *id,
            const crm_time_t *now, crm_time_t *next_change)
{
    crm_time_t *start = NULL;

    if (pcmk__xe_get_datetime(date_expression, PCMK_XA_START,
                              &start) != pcmk_rc_ok) {
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error
         */
        pcmk__config_warn("Treating " PCMK_XE_DATE_EXPRESSION " %s as not "
                          "passing because " PCMK_XA_START " is invalid",
                          id);
        return pcmk_rc_undetermined;
    }

    if (start == NULL) { // Not possible with schema validation enabled
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error
         */
        pcmk__config_warn("Treating " PCMK_XE_DATE_EXPRESSION " %s as not "
                          "passing because " PCMK_VALUE_GT " requires "
                          PCMK_XA_START, id);
        return pcmk_rc_undetermined;
    }

    if (crm_time_compare(now, start) > 0) {
        crm_time_free(start);
        return pcmk_rc_within_range;
    }

    // Evaluation doesn't change until second after start time
    crm_time_add_seconds(start, 1);
    pcmk__set_time_if_earlier(next_change, start);
    crm_time_free(start);
    return pcmk_rc_before_range;
}

/*!
 * \internal
 * \brief Evaluate a less-than check for a given date/time
 *
 * \param[in]     date_expression  XML of PCMK_XE_DATE_EXPRESSION element
 * \param[in]     id               Expression ID for logging purposes
 * \param[in]     now              Date/time to compare
 * \param[in,out] next_change      If not NULL, set this to when the evaluation
 *                                 will change, if known and earlier than the
 *                                 original value
 *
 * \return Standard Pacemaker return code
 */
static int
evaluate_lt(const xmlNode *date_expression, const char *id,
            const crm_time_t *now, crm_time_t *next_change)
{
    crm_time_t *end = NULL;

    if (pcmk__xe_get_datetime(date_expression, PCMK_XA_END,
                              &end) != pcmk_rc_ok) {
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error
         */
        pcmk__config_warn("Treating " PCMK_XE_DATE_EXPRESSION " %s as not "
                          "passing because " PCMK_XA_END " is invalid", id);
        return pcmk_rc_undetermined;
    }

    if (end == NULL) { // Not possible with schema validation enabled
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error
         */
        pcmk__config_warn("Treating " PCMK_XE_DATE_EXPRESSION " %s as not "
                          "passing because " PCMK_VALUE_GT " requires "
                          PCMK_XA_END, id);
        return pcmk_rc_undetermined;
    }

    if (crm_time_compare(now, end) < 0) {
        pcmk__set_time_if_earlier(next_change, end);
        crm_time_free(end);
        return pcmk_rc_within_range;
    }

    crm_time_free(end);
    return pcmk_rc_after_range;
}

/*!
 * \internal
 * \brief Evaluate a rule's date expression for a given date/time
 *
 * \param[in]     date_expression  XML of a PCMK_XE_DATE_EXPRESSION element
 * \param[in]     now              Time to use for evaluation
 * \param[in,out] next_change      If not NULL, set this to when the evaluation
 *                                 will change, if known and earlier than the
 *                                 original value
 *
 * \return Standard Pacemaker return code (unlike most other evaluation
 *         functions, this can return either pcmk_rc_ok or pcmk_rc_within_range
 *         on success)
 */
int
pcmk__evaluate_date_expression(const xmlNode *date_expression,
                               const crm_time_t *now, crm_time_t *next_change)
{
    const char *id = NULL;
    const char *op = NULL;
    int rc = pcmk_rc_undetermined;

    if ((date_expression == NULL) || (now == NULL)) {
        return EINVAL;
    }

    // Get expression ID (for logging)
    id = pcmk__xe_id(date_expression);
    if (pcmk__str_empty(id)) { // Not possible with schema validation enabled
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error
         */
        pcmk__config_warn(PCMK_XE_DATE_EXPRESSION " element has no "
                          PCMK_XA_ID);
        id = "without ID"; // for logging
    }

    op = crm_element_value(date_expression, PCMK_XA_OPERATION);
    if (pcmk__str_eq(op, PCMK_VALUE_IN_RANGE,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        rc = evaluate_in_range(date_expression, id, now, next_change);

    } else if (pcmk__str_eq(op, PCMK_VALUE_DATE_SPEC, pcmk__str_casei)) {
        xmlNode *date_spec = pcmk__xe_first_child(date_expression,
                                                  PCMK_XE_DATE_SPEC, NULL,
                                                  NULL);

        if (date_spec == NULL) { // Not possible with schema validation enabled
            /* @COMPAT When we can break behavioral backward compatibility,
             * return pcmk_rc_unpack_error
             */
            pcmk__config_warn("Treating " PCMK_XE_DATE_EXPRESSION " %s "
                              "as not passing because " PCMK_VALUE_DATE_SPEC
                              " operations require a " PCMK_XE_DATE_SPEC
                              " subelement", id);
        } else {
            // @TODO set next_change appropriately
            rc = pcmk__evaluate_date_spec(date_spec, now);
        }

    } else if (pcmk__str_eq(op, PCMK_VALUE_GT, pcmk__str_casei)) {
        rc = evaluate_gt(date_expression, id, now, next_change);

    } else if (pcmk__str_eq(op, PCMK_VALUE_LT, pcmk__str_casei)) {
        rc = evaluate_lt(date_expression, id, now, next_change);

    } else { // Not possible with schema validation enabled
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_unpack_error
         */
        pcmk__config_warn("Treating " PCMK_XE_DATE_EXPRESSION
                          " %s as not passing because '%s' is not a valid "
                          PCMK_XE_OPERATION, op);
    }

    crm_trace(PCMK_XE_DATE_EXPRESSION " %s (%s): %s (%d)",
              id, op, pcmk_rc_str(rc), rc);
    return rc;
}

/*!
 * \internal
 * \brief Go through submatches in a string, either counting how many bytes
 *        would be needed for the expansion, or performing the expansion,
 *        as requested
 *
 * \param[in]  string      String possibly containing submatch variables
 * \param[in]  match       String that matched the regular expression
 * \param[in]  submatches  Regular expression submatches (as set by regexec())
 * \param[in]  nmatches    Number of entries in \p submatches[]
 * \param[out] expansion   If not NULL, expand string here (must be
 *                         pre-allocated to appropriate size)
 * \param[out] nbytes      If not NULL, set to size needed for expansion
 *
 * \return true if any expansion is needed, otherwise false
 */
static bool
process_submatches(const char *string, const char *match,
                   const regmatch_t submatches[], int nmatches,
                   char *expansion, size_t *nbytes)
{
    bool expanded = false;
    const char *src = string;

    if (nbytes != NULL) {
        *nbytes = 1; // Include space for terminator
    }

    while (*src != '\0') {
        int submatch = 0;
        size_t match_len = 0;

        if ((src[0] != '%') || !isdigit(src[1])) {
            /* src does not point to the first character of a %N sequence,
             * so expand this character as-is
             */
            if (expansion != NULL) {
                *expansion++ = *src;
            }
            if (nbytes != NULL) {
                ++(*nbytes);
            }
            ++src;
            continue;
        }

        submatch = src[1] - '0';
        src += 2; // Skip over %N sequence in source string
        expanded = true; // Expansion will be different from source

        // Omit sequence from expansion unless it has a non-empty match
        if ((nmatches <= submatch)                // Not enough submatches
            || (submatches[submatch].rm_so < 0)   // Pattern did not match
            || (submatches[submatch].rm_eo
                <= submatches[submatch].rm_so)) { // Match was empty
            continue;
        }

        match_len = submatches[submatch].rm_eo - submatches[submatch].rm_so;
        if (nbytes != NULL) {
            *nbytes += match_len;
        }
        if (expansion != NULL) {
            memcpy(expansion, match + submatches[submatch].rm_so,
                   match_len);
            expansion += match_len;
        }
    }

    return expanded;
}

/*!
 * \internal
 * \brief Expand any regular expression submatches (%0-%9) in a string
 *
 * \param[in] string      String possibly containing submatch variables
 * \param[in] match       String that matched the regular expression
 * \param[in] submatches  Regular expression submatches (as set by regexec())
 * \param[in] nmatches    Number of entries in \p submatches[]
 *
 * \return Newly allocated string identical to \p string with submatches
 *         expanded on success, or NULL if no expansions were needed
 * \note The caller is responsible for freeing the result with free()
 */
char *
pcmk__replace_submatches(const char *string, const char *match,
                         const regmatch_t submatches[], int nmatches)
{
    size_t nbytes = 0;
    char *result = NULL;

    if (pcmk__str_empty(string) || pcmk__str_empty(match)) {
        return NULL; // Nothing to expand
    }

    // Calculate how much space will be needed for expanded string
    if (!process_submatches(string, match, submatches, nmatches, NULL,
                            &nbytes)) {
        return NULL; // No expansions needed
    }

    // Allocate enough space for expanded string
    result = pcmk__assert_alloc(nbytes, sizeof(char));

    // Expand submatches
    (void) process_submatches(string, match, submatches, nmatches, result,
                              NULL);
    return result;
}

/*!
 * \internal
 * \brief Parse a comparison type from a string
 *
 * \param[in] op  String with comparison type (valid values are
 *                \c PCMK_VALUE_DEFINED, \c PCMK_VALUE_NOT_DEFINED,
 *                \c PCMK_VALUE_EQ, \c PCMK_VALUE_NE,
 *                \c PCMK_VALUE_LT, \c PCMK_VALUE_LTE,
 *                \c PCMK_VALUE_GT, or \c PCMK_VALUE_GTE)
 *
 * \return Comparison type corresponding to \p op
 */
enum pcmk__comparison
pcmk__parse_comparison(const char *op)
{
    if (pcmk__str_eq(op, PCMK_VALUE_DEFINED, pcmk__str_casei)) {
        return pcmk__comparison_defined;

    } else if (pcmk__str_eq(op, PCMK_VALUE_NOT_DEFINED, pcmk__str_casei)) {
        return pcmk__comparison_undefined;

    } else if (pcmk__str_eq(op, PCMK_VALUE_EQ, pcmk__str_casei)) {
        return pcmk__comparison_eq;

    } else if (pcmk__str_eq(op, PCMK_VALUE_NE, pcmk__str_casei)) {
        return pcmk__comparison_ne;

    } else if (pcmk__str_eq(op, PCMK_VALUE_LT, pcmk__str_casei)) {
        return pcmk__comparison_lt;

    } else if (pcmk__str_eq(op, PCMK_VALUE_LTE, pcmk__str_casei)) {
        return pcmk__comparison_lte;

    } else if (pcmk__str_eq(op, PCMK_VALUE_GT, pcmk__str_casei)) {
        return pcmk__comparison_gt;

    } else if (pcmk__str_eq(op, PCMK_VALUE_GTE, pcmk__str_casei)) {
        return pcmk__comparison_gte;
    }

    return pcmk__comparison_unknown;
}

/*!
 * \internal
 * \brief Parse a value type from a string
 *
 * \param[in] type    String with value type (valid values are NULL,
 *                    \c PCMK_VALUE_STRING, \c PCMK_VALUE_INTEGER,
 *                    \c PCMK_VALUE_NUMBER, and \c PCMK_VALUE_VERSION)
 * \param[in] op      Operation type (used only to select default)
 * \param[in] value1  First value being compared (used only to select default)
 * \param[in] value2  Second value being compared (used only to select default)
 */
enum pcmk__type
pcmk__parse_type(const char *type, enum pcmk__comparison op,
                 const char *value1, const char *value2)
{
    if (type == NULL) {
        switch (op) {
            case pcmk__comparison_lt:
            case pcmk__comparison_lte:
            case pcmk__comparison_gt:
            case pcmk__comparison_gte:
                if (((value1 != NULL) && (strchr(value1, '.') != NULL))
                    || ((value2 != NULL) && (strchr(value2, '.') != NULL))) {
                    return pcmk__type_number;
                }
                return pcmk__type_integer;

            default:
                return pcmk__type_string;
        }
    }

    if (pcmk__str_eq(type, PCMK_VALUE_STRING, pcmk__str_casei)) {
        return pcmk__type_string;

    } else if (pcmk__str_eq(type, PCMK_VALUE_INTEGER, pcmk__str_casei)) {
        return pcmk__type_integer;

    } else if (pcmk__str_eq(type, PCMK_VALUE_NUMBER, pcmk__str_casei)) {
        return pcmk__type_number;

    } else if (pcmk__str_eq(type, PCMK_VALUE_VERSION, pcmk__str_casei)) {
        return pcmk__type_version;
    }

    return pcmk__type_unknown;
}

/*!
 * \internal
 * \brief Compare two strings according to a given type
 *
 * \param[in] value1  String with first value to compare
 * \param[in] value2  String with second value to compare
 * \param[in] type    How to interpret the values
 *
 * \return Standard comparison result (a negative integer if \p value1 is
 *         lesser, 0 if the values are equal, and a positive integer if
 *         \p value1 is greater)
 */
int
pcmk__cmp_by_type(const char *value1, const char *value2, enum pcmk__type type)
{
    //  NULL compares as less than non-NULL
    if (value2 == NULL) {
        return (value1 == NULL)? 0 : 1;
    }
    if (value1 == NULL) {
        return -1;
    }

    switch (type) {
        case pcmk__type_string:
            return strcasecmp(value1, value2);

        case pcmk__type_integer:
            {
                long long integer1;
                long long integer2;

                if ((pcmk__scan_ll(value1, &integer1, 0LL) != pcmk_rc_ok)
                    || (pcmk__scan_ll(value2, &integer2, 0LL) != pcmk_rc_ok)) {
                    crm_warn("Comparing '%s' and '%s' as strings because "
                             "invalid as integers", value1, value2);
                    return strcasecmp(value1, value2);
                }
                return (integer1 < integer2)? -1 : (integer1 > integer2)? 1 : 0;
            }
            break;

        case pcmk__type_number:
            {
                double num1;
                double num2;

                if ((pcmk__scan_double(value1, &num1, NULL, NULL) != pcmk_rc_ok)
                    || (pcmk__scan_double(value2, &num2, NULL,
                                          NULL) != pcmk_rc_ok)) {
                    crm_warn("Comparing '%s' and '%s' as strings because invalid as "
                             "numbers", value1, value2);
                    return strcasecmp(value1, value2);
                }
                return (num1 < num2)? -1 : (num1 > num2)? 1 : 0;
            }
            break;

        case pcmk__type_version:
            return compare_version(value1, value2);

        default: // Invalid type
            return 0;
    }
}

/*!
 * \internal
 * \brief Parse a reference value source from a string
 *
 * \param[in] source  String indicating reference value source
 *
 * \return Reference value source corresponding to \p source
 */
enum pcmk__reference_source
pcmk__parse_source(const char *source)
{
    if (pcmk__str_eq(source, PCMK_VALUE_LITERAL,
                     pcmk__str_casei|pcmk__str_null_matches)) {
        return pcmk__source_literal;

    } else if (pcmk__str_eq(source, PCMK_VALUE_PARAM, pcmk__str_casei)) {
        return pcmk__source_instance_attrs;

    } else if (pcmk__str_eq(source, PCMK_VALUE_META, pcmk__str_casei)) {
        return pcmk__source_meta_attrs;

    } else {
        return pcmk__source_unknown;
    }
}

/*!
 * \internal
 * \brief Parse a boolean operator from a string
 *
 * \param[in] combine  String indicating boolean operator
 *
 * \return Enumeration value corresponding to \p combine
 */
enum pcmk__combine
pcmk__parse_combine(const char *combine)
{
    if (pcmk__str_eq(combine, PCMK_VALUE_AND,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        return pcmk__combine_and;

    } else if (pcmk__str_eq(combine, PCMK_VALUE_OR, pcmk__str_casei)) {
        return pcmk__combine_or;

    } else {
        return pcmk__combine_unknown;
    }
}

/*!
 * \internal
 * \brief Get the result of a node attribute comparison for rule evaluation
 *
 * \param[in] actual      Actual node attribute value
 * \param[in] reference   Node attribute value from rule (ignored for
 *                        \p comparison of \c pcmk__comparison_defined or
 *                        \c pcmk__comparison_undefined)
 * \param[in] type        How to interpret the values
 * \param[in] comparison  How to compare the values
 *
 * \return Standard Pacemaker return code (specifically, \c pcmk_rc_ok if the
 *         comparison passes, and some other value if it does not)
 */
static int
evaluate_attr_comparison(const char *actual, const char *reference,
                         enum pcmk__type type, enum pcmk__comparison comparison)
{
    int cmp = 0;

    switch (comparison) {
        case pcmk__comparison_defined:
            return (actual != NULL)? pcmk_rc_ok : pcmk_rc_op_unsatisfied;

        case pcmk__comparison_undefined:
            return (actual == NULL)? pcmk_rc_ok : pcmk_rc_op_unsatisfied;

        default:
            break;
    }

    cmp = pcmk__cmp_by_type(actual, reference, type);

    switch (comparison) {
        case pcmk__comparison_eq:
            return (cmp == 0)? pcmk_rc_ok : pcmk_rc_op_unsatisfied;

        case pcmk__comparison_ne:
            return (cmp != 0)? pcmk_rc_ok : pcmk_rc_op_unsatisfied;

        default:
            break;
    }

    if ((actual == NULL) || (reference == NULL)) {
        return pcmk_rc_op_unsatisfied; // Comparison would be meaningless
    }

    switch (comparison) {
        case pcmk__comparison_lt:
            return (cmp < 0)? pcmk_rc_ok : pcmk_rc_after_range;

        case pcmk__comparison_lte:
            return (cmp <= 0)? pcmk_rc_ok : pcmk_rc_after_range;

        case pcmk__comparison_gt:
            return (cmp > 0)? pcmk_rc_ok : pcmk_rc_before_range;

        case pcmk__comparison_gte:
            return (cmp >= 0)? pcmk_rc_ok : pcmk_rc_before_range;

        default: // Not possible with schema validation enabled
            return pcmk_rc_op_unsatisfied;
    }
}

/*!
 * \internal
 * \brief Get a reference value from a configured source
 *
 * \param[in] value       Value given in rule expression
 * \param[in] source      Reference value source
 * \param[in] rule_input  Values used to evaluate rule criteria
 */
static const char *
value_from_source(const char *value, enum pcmk__reference_source source,
                  const pcmk_rule_input_t *rule_input)
{
    GHashTable *table = NULL;

    if (pcmk__str_empty(value)) {
        /* @COMPAT When we can break backward compatibility, drop this block so
         * empty strings are treated as such (there should never be an empty
         * string as an instance attribute or meta-attribute name, so those will
         * get NULL anyway, but it could matter for literal comparisons)
         */
        return NULL;
    }

    switch (source) {
        case pcmk__source_literal:
            return value;

        case pcmk__source_instance_attrs:
            table = rule_input->rsc_params;
            break;

        case pcmk__source_meta_attrs:
            table = rule_input->rsc_meta;
            break;

        default:
            return NULL; // Not possible
    }

    if (table == NULL) {
        return NULL;
    }
    return (const char *) g_hash_table_lookup(table, value);
}

/*!
 * \internal
 * \brief Evaluate a node attribute rule expression
 *
 * \param[in] expression  XML of a rule's PCMK_XE_EXPRESSION subelement
 * \param[in] rule_input  Values used to evaluate rule criteria
 *
 * \return Standard Pacemaker return code (\c pcmk_rc_ok if the expression
 *         passes, some other value if it does not)
 */
int
pcmk__evaluate_attr_expression(const xmlNode *expression,
                               const pcmk_rule_input_t *rule_input)
{
    const char *id = NULL;
    const char *op = NULL;
    const char *attr = NULL;
    const char *type_s = NULL;
    const char *value = NULL;
    const char *actual = NULL;
    const char *source_s = NULL;
    const char *reference = NULL;
    char *expanded_attr = NULL;
    int rc = pcmk_rc_ok;

    enum pcmk__type type = pcmk__type_unknown;
    enum pcmk__reference_source source = pcmk__source_unknown;
    enum pcmk__comparison comparison = pcmk__comparison_unknown;

    if ((expression == NULL) || (rule_input == NULL)) {
        return EINVAL;
    }

    // Get expression ID (for logging)
    id = pcmk__xe_id(expression);
    if (pcmk__str_empty(id)) {
        /* @COMPAT When we can break behavioral backward compatibility,
         * fail the expression
         */
        pcmk__config_warn(PCMK_XE_EXPRESSION " element has no " PCMK_XA_ID);
        id = "without ID"; // for logging
    }

    /* Get name of node attribute to compare (expanding any %0-%9 to
     * regular expression submatches)
     */
    attr = crm_element_value(expression, PCMK_XA_ATTRIBUTE);
    if (pcmk__str_empty(attr)) {
        pcmk__config_err("Treating " PCMK_XE_EXPRESSION " %s as not passing "
                         "because " PCMK_XA_ATTRIBUTE " was not specified", id);
        return pcmk_rc_unpack_error;
    }
    expanded_attr = pcmk__replace_submatches(attr, rule_input->rsc_id,
                                             rule_input->rsc_id_submatches,
                                             rule_input->rsc_id_nmatches);
    if (expanded_attr != NULL) {
        attr = expanded_attr;
    }

    // Get and validate operation
    op = crm_element_value(expression, PCMK_XA_OPERATION);
    comparison = pcmk__parse_comparison(op);
    if (comparison == pcmk__comparison_unknown) {
        // Not possible with schema validation enabled
        if (op == NULL) {
            pcmk__config_err("Treating " PCMK_XE_EXPRESSION " %s as not "
                             "passing because it has no " PCMK_XA_OPERATION,
                             id);
        } else {
            pcmk__config_err("Treating " PCMK_XE_EXPRESSION " %s as not "
                             "passing because '%s' is not a valid "
                             PCMK_XA_OPERATION, id, op);
        }
        rc = pcmk_rc_unpack_error;
        goto done;
    }

    // How reference value is obtained (literal, resource meta-attribute, etc.)
    source_s = crm_element_value(expression, PCMK_XA_VALUE_SOURCE);
    source = pcmk__parse_source(source_s);
    if (source == pcmk__source_unknown) {
        // Not possible with schema validation enabled
        // @COMPAT Fail expression once we can break backward compatibility
        pcmk__config_warn("Expression %s has invalid " PCMK_XA_VALUE_SOURCE
                          " value '%s', using default "
                          "('" PCMK_VALUE_LITERAL "')", id, source_s);
        source = pcmk__source_literal;
    }

    // Get and validate reference value
    value = crm_element_value(expression, PCMK_XA_VALUE);
    switch (comparison) {
        case pcmk__comparison_defined:
        case pcmk__comparison_undefined:
            if (value != NULL) {
                pcmk__config_warn("Ignoring " PCMK_XA_VALUE " in "
                                  PCMK_XE_EXPRESSION " %s because it is unused "
                                  "when " PCMK_XA_BOOLEAN_OP " is %s", id, op);
            }
            break;

        default:
            if (value == NULL) {
                pcmk__config_warn(PCMK_XE_EXPRESSION " %s has no "
                                  PCMK_XA_VALUE, id);
            }
            break;
    }
    reference = value_from_source(value, source, rule_input);

    // Get actual value of node attribute
    if (rule_input->node_attrs != NULL) {
        actual = g_hash_table_lookup(rule_input->node_attrs, attr);
    }

    // Get and validate value type (after expanding reference value)
    type_s = crm_element_value(expression, PCMK_XA_TYPE);
    type = pcmk__parse_type(type_s, comparison, actual, reference);
    if (type == pcmk__type_unknown) {
        /* Not possible with schema validation enabled
         *
         * @COMPAT When we can break behavioral backward compatibility, treat
         * the expression as not passing.
         */
        pcmk__config_warn("Non-empty node attribute values will be treated as "
                          "equal for " PCMK_XE_EXPRESSION " %s because '%s' "
                          "is not a valid type", id, type);
    }

    rc = evaluate_attr_comparison(actual, reference, type, comparison);
    switch (comparison) {
        case pcmk__comparison_defined:
        case pcmk__comparison_undefined:
            crm_trace(PCMK_XE_EXPRESSION " %s result: %s (for attribute %s %s)",
                      id, pcmk_rc_str(rc), attr, op);
            break;

        default:
            crm_trace(PCMK_XE_EXPRESSION " %s result: "
                      "%s (attribute %s %s '%s' via %s source as %s type)",
                      id, pcmk_rc_str(rc), attr, op, pcmk__s(reference, ""),
                      pcmk__s(source_s, "default"), pcmk__s(type_s, "default"));
            break;
    }

done:
    free(expanded_attr);
    return rc;
}

/*!
 * \internal
 * \brief Evaluate a resource rule expression
 *
 * \param[in] rsc_expression  XML of rule's \c PCMK_XE_RSC_EXPRESSION subelement
 * \param[in] rule_input      Values used to evaluate rule criteria
 *
 * \return Standard Pacemaker return code (\c pcmk_rc_ok if the expression
 *         passes, some other value if it does not)
 */
int
pcmk__evaluate_rsc_expression(const xmlNode *rsc_expression,
                              const pcmk_rule_input_t *rule_input)
{
    const char *id = NULL;
    const char *standard = NULL;
    const char *provider = NULL;
    const char *type = NULL;

    if ((rsc_expression == NULL) || (rule_input == NULL)) {
        return EINVAL;
    }

    // Validate XML ID
    id = pcmk__xe_id(rsc_expression);
    if (pcmk__str_empty(id)) {
        // Not possible with schema validation enabled
        /* @COMPAT When we can break behavioral backward compatibility,
         * fail the expression
         */
        pcmk__config_warn(PCMK_XE_RSC_EXPRESSION " has no " PCMK_XA_ID);
        id = "without ID"; // for logging
    }

    // Compare resource standard
    standard = crm_element_value(rsc_expression, PCMK_XA_CLASS);
    if ((standard != NULL)
        && !pcmk__str_eq(standard, rule_input->rsc_standard, pcmk__str_none)) {
        crm_trace(PCMK_XE_RSC_EXPRESSION " %s is unsatisfied because "
                  "actual standard '%s' doesn't match '%s'",
                  id, pcmk__s(rule_input->rsc_standard, ""), standard);
        return pcmk_rc_op_unsatisfied;
    }

    // Compare resource provider
    provider = crm_element_value(rsc_expression, PCMK_XA_PROVIDER);
    if ((provider != NULL)
        && !pcmk__str_eq(provider, rule_input->rsc_provider, pcmk__str_none)) {
        crm_trace(PCMK_XE_RSC_EXPRESSION " %s is unsatisfied because "
                  "actual provider '%s' doesn't match '%s'",
                  id, pcmk__s(rule_input->rsc_provider, ""), provider);
        return pcmk_rc_op_unsatisfied;
    }

    // Compare resource agent type
    type = crm_element_value(rsc_expression, PCMK_XA_TYPE);
    if ((type != NULL)
        && !pcmk__str_eq(type, rule_input->rsc_agent, pcmk__str_none)) {
        crm_trace(PCMK_XE_RSC_EXPRESSION " %s is unsatisfied because "
                  "actual agent '%s' doesn't match '%s'",
                  id, pcmk__s(rule_input->rsc_agent, ""), type);
        return pcmk_rc_op_unsatisfied;
    }

    crm_trace(PCMK_XE_RSC_EXPRESSION " %s is satisfied by %s%s%s:%s",
              id, pcmk__s(standard, ""),
              ((provider == NULL)? "" : ":"), pcmk__s(provider, ""),
              pcmk__s(type, ""));
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Evaluate an operation rule expression
 *
 * \param[in] op_expression  XML of a rule's \c PCMK_XE_OP_EXPRESSION subelement
 * \param[in] rule_input     Values used to evaluate rule criteria
 *
 * \return Standard Pacemaker return code (\c pcmk_rc_ok if the expression
 *         is satisfied, some other value if it is not)
 */
int
pcmk__evaluate_op_expression(const xmlNode *op_expression,
                             const pcmk_rule_input_t *rule_input)
{
    const char *id = NULL;
    const char *name = NULL;
    const char *interval_s = NULL;
    guint interval_ms = 0U;

    if ((op_expression == NULL) || (rule_input == NULL)) {
        return EINVAL;
    }

    // Get operation expression ID (for logging)
    id = pcmk__xe_id(op_expression);
    if (pcmk__str_empty(id)) { // Not possible with schema validation enabled
        /* @COMPAT When we can break behavioral backward compatibility,
         * return pcmk_rc_op_unsatisfied
         */
        pcmk__config_warn(PCMK_XE_OP_EXPRESSION " element has no " PCMK_XA_ID);
        id = "without ID"; // for logging
    }

    // Validate operation name
    name = crm_element_value(op_expression, PCMK_XA_NAME);
    if (name == NULL) { // Not possible with schema validation enabled
        pcmk__config_warn("Treating " PCMK_XE_OP_EXPRESSION " %s as not "
                          "passing because it has no " PCMK_XA_NAME, id);
        return pcmk_rc_unpack_error;
    }

    // Validate operation interval
    interval_s = crm_element_value(op_expression, PCMK_META_INTERVAL);
    if (pcmk_parse_interval_spec(interval_s, &interval_ms) != pcmk_rc_ok) {
        pcmk__config_warn("Treating " PCMK_XE_OP_EXPRESSION " %s as not "
                          "passing because '%s' is not a valid interval",
                          id, interval_s);
        return pcmk_rc_unpack_error;
    }

    // Compare operation name
    if (!pcmk__str_eq(name, rule_input->op_name, pcmk__str_none)) {
        crm_trace(PCMK_XE_OP_EXPRESSION " %s is unsatisfied because "
                  "actual name '%s' doesn't match '%s'",
                  id, pcmk__s(rule_input->op_name, ""), name);
        return pcmk_rc_op_unsatisfied;
    }

    // Compare operation interval (unspecified interval matches all)
    if ((interval_s != NULL) && (interval_ms != rule_input->op_interval_ms)) {
        crm_trace(PCMK_XE_OP_EXPRESSION " %s is unsatisfied because "
                  "actual interval %s doesn't match %s",
                  id, pcmk__readable_interval(rule_input->op_interval_ms),
                  pcmk__readable_interval(interval_ms));
        return pcmk_rc_op_unsatisfied;
    }

    crm_trace(PCMK_XE_OP_EXPRESSION " %s is satisfied (name %s, interval %s)",
              id, name, pcmk__readable_interval(rule_input->op_interval_ms));
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Evaluate a rule condition
 *
 * \param[in,out] condition    XML containing a rule condition (a subrule, or an
 *                             expression of any type)
 * \param[in]     rule_input   Values used to evaluate rule criteria
 * \param[out]    next_change  If not NULL, set to when evaluation will change
 *
 * \return Standard Pacemaker return code (\c pcmk_rc_ok if the condition
 *         passes, some other value if it does not)
 */
int
pcmk__evaluate_condition(xmlNode *condition,
                         const pcmk_rule_input_t *rule_input,
                         crm_time_t *next_change)
{

    if ((condition == NULL) || (rule_input == NULL)) {
        return EINVAL;
    }

    switch (pcmk__expression_type(condition)) {
        case pcmk__subexpr_rule:
            return pcmk_evaluate_rule(condition, rule_input, next_change);

        case pcmk__subexpr_attribute:
        case pcmk__subexpr_location:
            return pcmk__evaluate_attr_expression(condition, rule_input);

        case pcmk__subexpr_datetime:
            {
                int rc = pcmk__evaluate_date_expression(condition,
                                                        rule_input->now,
                                                        next_change);

                return (rc == pcmk_rc_within_range)? pcmk_rc_ok : rc;
            }

        case pcmk__subexpr_resource:
            return pcmk__evaluate_rsc_expression(condition, rule_input);

        case pcmk__subexpr_operation:
            return pcmk__evaluate_op_expression(condition, rule_input);

        default: // Not possible with schema validation enabled
            pcmk__config_err("Treating rule condition %s as not passing "
                             "because %s is not a valid condition type",
                             pcmk__s(pcmk__xe_id(condition), "without ID"),
                             (const char *) condition->name);
            return pcmk_rc_unpack_error;
    }
}

/*!
 * \brief Evaluate a single rule, including all its conditions
 *
 * \param[in,out] rule         XML containing a rule definition or its id-ref
 * \param[in]     rule_input   Values used to evaluate rule criteria
 * \param[out]    next_change  If not NULL, set to when evaluation will change
 *
 * \return Standard Pacemaker return code (\c pcmk_rc_ok if the rule is
 *         satisfied, some other value if it is not)
 */
int
pcmk_evaluate_rule(xmlNode *rule, const pcmk_rule_input_t *rule_input,
                   crm_time_t *next_change)
{
    bool empty = true;
    int rc = pcmk_rc_ok;
    const char *id = NULL;
    const char *value = NULL;
    enum pcmk__combine combine = pcmk__combine_unknown;

    if ((rule == NULL) || (rule_input == NULL)) {
        return EINVAL;
    }

    rule = expand_idref(rule, NULL);
    if (rule == NULL) {
        // Not possible with schema validation enabled; message already logged
        return pcmk_rc_unpack_error;
    }

    // Validate XML ID
    id = pcmk__xe_id(rule);
    if (pcmk__str_empty(id)) {
        /* @COMPAT When we can break behavioral backward compatibility,
         * fail the rule
         */
        pcmk__config_warn(PCMK_XE_RULE " has no " PCMK_XA_ID);
        id = "without ID"; // for logging
    }

    value = crm_element_value(rule, PCMK_XA_BOOLEAN_OP);
    combine = pcmk__parse_combine(value);
    switch (combine) {
        case pcmk__combine_and:
            // For "and", rc defaults to success (reset on failure below)
            break;

        case pcmk__combine_or:
            // For "or", rc defaults to failure (reset on success below)
            rc = pcmk_rc_op_unsatisfied;
            break;

        default:
            /* @COMPAT When we can break behavioral backward compatibility,
             * return pcmk_rc_unpack_error
             */
            pcmk__config_warn("Rule %s has invalid " PCMK_XA_BOOLEAN_OP
                              " value '%s', using default '" PCMK_VALUE_AND "'",
                              pcmk__xe_id(rule), value);
            combine = pcmk__combine_and;
            break;
    }

    // Evaluate each condition
    for (xmlNode *condition = pcmk__xe_first_child(rule, NULL, NULL, NULL);
         condition != NULL; condition = pcmk__xe_next(condition)) {

        empty = false;
        if (pcmk__evaluate_condition(condition, rule_input,
                                     next_change) == pcmk_rc_ok) {
            if (combine == pcmk__combine_or) {
                rc = pcmk_rc_ok; // Any pass is final for "or"
                break;
            }
        } else if (combine == pcmk__combine_and) {
            rc = pcmk_rc_op_unsatisfied; // Any failure is final for "and"
            break;
        }
    }

    if (empty) { // Not possible with schema validation enabled
        /* @COMPAT Currently, we don't actually ignore "or" rules because
         * rc is initialized to failure above in that case. When we can break
         * backward compatibility, reset rc to pcmk_rc_ok here.
         */
        pcmk__config_warn("Ignoring rule %s because it contains no conditions",
                          id);
    }

    crm_trace("Rule %s is %ssatisfied", id, ((rc == pcmk_rc_ok)? "" : "not "));
    return rc;
}
