/*
 * Copyright 2020-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/msg_xml.h>
#include <crm/common/unittest_internal.h>
#include <crm/common/xml.h>
#include <crm/pengine/rules_internal.h>

static void
run_one_test(const char *t, const char *x, int expected) {
    crm_time_t *tm = crm_time_new(t);
    xmlNodePtr xml = string2xml(x);

    assert_int_equal(pe_cron_range_satisfied(tm, xml), expected);

    crm_time_free(tm);
    free_xml(xml);
}

static void
no_time_given(void **state) {
    assert_int_equal(pe_cron_range_satisfied(NULL, NULL), pcmk_rc_op_unsatisfied);
}

static void
any_time_satisfies_empty_spec(void **state) {
    crm_time_t *tm = crm_time_new(NULL);

    assert_int_equal(pe_cron_range_satisfied(tm, NULL), pcmk_rc_ok);

    crm_time_free(tm);
}

static void
time_satisfies_year_spec(void **state) {
    run_one_test("2020-01-01",
                 "<date_spec " XML_ATTR_ID "='spec' years='2020'/>",
                 pcmk_rc_ok);
}

static void
time_after_year_spec(void **state) {
    run_one_test("2020-01-01",
                 "<date_spec " XML_ATTR_ID "='spec' years='2019'/>",
                 pcmk_rc_after_range);
}

static void
time_satisfies_year_range(void **state) {
    run_one_test("2020-01-01",
                 "<date_spec " XML_ATTR_ID "='spec' years='2010-2030'/>",
                 pcmk_rc_ok);
}

static void
time_before_year_range(void **state) {
    run_one_test("2000-01-01",
                 "<date_spec " XML_ATTR_ID "='spec' years='2010-2030'/>",
                 pcmk_rc_before_range);
}

static void
time_after_year_range(void **state) {
    run_one_test("2020-01-01",
                 "<date_spec " XML_ATTR_ID "='spec' years='2010-2015'/>",
                 pcmk_rc_after_range);
}

static void
range_without_start_year_passes(void **state) {
    run_one_test("2010-01-01",
                 "<date_spec " XML_ATTR_ID "='spec' years='-2020'/>",
                 pcmk_rc_ok);
}

static void
range_without_end_year_passes(void **state) {
    run_one_test("2010-01-01",
                 "<date_spec " XML_ATTR_ID "='spec' years='2000-'/>",
                 pcmk_rc_ok);
    run_one_test("2000-10-01",
                 "<date_spec " XML_ATTR_ID "='spec' years='2000-'/>",
                 pcmk_rc_ok);
}

static void
yeardays_satisfies(void **state) {
    run_one_test("2020-01-30",
                 "<date_spec " XML_ATTR_ID "='spec' yeardays='30'/>",
                 pcmk_rc_ok);
}

static void
time_after_yeardays_spec(void **state) {
    run_one_test("2020-02-15",
                 "<date_spec " XML_ATTR_ID "='spec' yeardays='40'/>",
                 pcmk_rc_after_range);
}

static void
yeardays_feb_29_satisfies(void **state) {
    run_one_test("2016-02-29",
                 "<date_spec " XML_ATTR_ID "='spec' yeardays='60'/>",
                 pcmk_rc_ok);
}

static void
exact_ymd_satisfies(void **state) {
    run_one_test("2001-12-31",
                 "<date_spec " XML_ATTR_ID "='spec' years='2001' months='12' "
                 "monthdays='31'/>",
                 pcmk_rc_ok);
}

static void
range_in_month_satisfies(void **state) {
    run_one_test("2001-06-10",
                 "<date_spec " XML_ATTR_ID "='spec' years='2001' months='6' "
                 "monthdays='1-10'/>",
                 pcmk_rc_ok);
}

static void
exact_ymd_after_range(void **state) {
    run_one_test("2001-12-31",
                 "<date_spec " XML_ATTR_ID "='spec' years='2001' months='12' "
                 "monthdays='30'/>",
                 pcmk_rc_after_range);
}

static void
time_after_monthdays_range(void **state) {
    run_one_test("2001-06-10",
                 "<date_spec " XML_ATTR_ID "='spec' years='2001' months='6' "
                 "monthdays='11-15'/>",
                 pcmk_rc_before_range);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(no_time_given),
                cmocka_unit_test(any_time_satisfies_empty_spec),
                cmocka_unit_test(time_satisfies_year_spec),
                cmocka_unit_test(time_after_year_spec),
                cmocka_unit_test(time_satisfies_year_range),
                cmocka_unit_test(time_before_year_range),
                cmocka_unit_test(time_after_year_range),
                cmocka_unit_test(range_without_start_year_passes),
                cmocka_unit_test(range_without_end_year_passes),
                cmocka_unit_test(yeardays_satisfies),
                cmocka_unit_test(time_after_yeardays_spec),
                cmocka_unit_test(yeardays_feb_29_satisfies),
                cmocka_unit_test(exact_ymd_satisfies),
                cmocka_unit_test(range_in_month_satisfies),
                cmocka_unit_test(exact_ymd_after_range),
                cmocka_unit_test(time_after_monthdays_range))
