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

/* As per the nethack rules:
 *
 * moon period = 29.53058 days ~= 30, year = 365.2422 days
 * days moon phase advances on first day of year compared to preceding year
 *      = 365.2422 - 12*29.53058 ~= 11
 * years in Metonic cycle (time until same phases fall on the same days of
 *      the month) = 18.6 ~= 19
 * moon phase on first day of year (epact) ~= (11*(year%19) + 29) % 30
 *      (29 as initial condition)
 * current phase in days = first day phase + days elapsed in year
 * 6 moons ~= 177 days
 * 177 ~= 8 reported phases * 22
 * + 11/22 for rounding
 *
 * 0-7, with 0: new, 4: full
 */

static int
phase_of_the_moon(const crm_time_t *now)
{
    uint32_t epact, diy, goldn;
    uint32_t y;

    crm_time_get_ordinal(now, &y, &diy);

    goldn = (y % 19) + 1;
    epact = (11 * goldn + 18) % 30;
    if ((epact == 25 && goldn > 11) || epact == 24)
        epact++;

    return ((((((diy + epact) * 6) + 11) % 177) / 22) & 7);
}

static int
check_one(const xmlNode *cron_spec, const char *xml_field, uint32_t time_field)
{
    int rc = pcmk_rc_undetermined;
    const char *value = crm_element_value(cron_spec, xml_field);
    long long low, high;

    if (value == NULL) {
        /* Return pe_date_result_undetermined if the field is missing. */
        goto bail;
    }

    if (pcmk__parse_ll_range(value, &low, &high) != pcmk_rc_ok) {
       goto bail;
    } else if (low == high) {
        /* A single number was given, not a range. */
        if (time_field < low) {
            rc = pcmk_rc_before_range;
        } else if (time_field > high) {
            rc = pcmk_rc_after_range;
        } else {
            rc = pcmk_rc_within_range;
        }
    } else if (low != -1 && high != -1) {
        /* This is a range with both bounds. */
        if (time_field < low) {
            rc = pcmk_rc_before_range;
        } else if (time_field > high) {
            rc = pcmk_rc_after_range;
        } else {
            rc = pcmk_rc_within_range;
        }
    } else if (low == -1) {
       /* This is a range with no starting value. */
        rc = time_field <= high ? pcmk_rc_within_range : pcmk_rc_after_range;
    } else if (high == -1) {
        /* This is a range with no ending value. */
        rc = time_field >= low ? pcmk_rc_within_range : pcmk_rc_before_range;
    }

bail:
    if (rc == pcmk_rc_within_range) {
        crm_debug("Condition '%s' in %s: passed", value, xml_field);
    } else {
        crm_debug("Condition '%s' in %s: failed", value, xml_field);
    }

    return rc;
}

static gboolean
check_passes(int rc) {
    /* _within_range is obvious.  _undetermined is a pass because
     * this is the return value if a field is not given.  In this
     * case, we just want to ignore it and check other fields to
     * see if they place some restriction on what can pass.
     */
    return rc == pcmk_rc_within_range || rc == pcmk_rc_undetermined;
}

#define CHECK_ONE(spec, name, var) do { \
    int subpart_rc = check_one(spec, name, var); \
    if (check_passes(subpart_rc) == FALSE) { \
        return subpart_rc; \
    } \
} while (0)

int
pe_cron_range_satisfied(const crm_time_t *now, const xmlNode *cron_spec)
{
    uint32_t h, m, s, y, d, w;

    CRM_CHECK(now != NULL, return pcmk_rc_op_unsatisfied);

    crm_time_get_gregorian(now, &y, &m, &d);
    CHECK_ONE(cron_spec, PCMK_XA_YEARS, y);
    CHECK_ONE(cron_spec, PCMK_XA_MONTHS, m);
    CHECK_ONE(cron_spec, PCMK_XA_MONTHDAYS, d);

    crm_time_get_timeofday(now, &h, &m, &s);
    CHECK_ONE(cron_spec, PCMK_XA_HOURS, h);
    CHECK_ONE(cron_spec, PCMK_XA_MINUTES, m);
    CHECK_ONE(cron_spec, PCMK_XA_SECONDS, s);

    crm_time_get_ordinal(now, &y, &d);
    CHECK_ONE(cron_spec, PCMK_XA_YEARDAYS, d);

    crm_time_get_isoweek(now, &y, &w, &d);
    CHECK_ONE(cron_spec, PCMK_XA_WEEKYEARS, y);
    CHECK_ONE(cron_spec, PCMK_XA_WEEKS, w);
    CHECK_ONE(cron_spec, PCMK_XA_WEEKDAYS, d);

    CHECK_ONE(cron_spec, PCMK__XA_MOON, phase_of_the_moon(now));
    if (crm_element_value(cron_spec, PCMK__XA_MOON) != NULL) {
        pcmk__config_warn("Support for '" PCMK__XA_MOON "' in "
                          PCMK_XE_DATE_SPEC " elements (such as %s) is "
                          "deprecated and will be removed in a future release "
                          "of Pacemaker",
                          pcmk__xe_id(cron_spec));
    }

    /* If we get here, either no fields were specified (which is success), or all
     * the fields that were specified had their conditions met (which is also a
     * success).  Thus, the result is success.
     */
    return pcmk_rc_ok;
}
