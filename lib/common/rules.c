/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>                          // NULL
#include <stdint.h>                         // uint32_t
#include <inttypes.h>                       // PRIu32
#include <glib.h>                           // gboolean, FALSE
#include <libxml/tree.h>                    // xmlNode

#include <crm/common/scheduler.h>
#include <crm/common/scheduler_internal.h>

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
        pcmk__config_warn(PCMK_XE_DATE_SPEC " element has no " PCMK_XA_ID);
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
