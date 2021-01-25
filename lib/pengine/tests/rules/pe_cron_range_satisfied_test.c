/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <glib.h>

#include <crm/common/xml.h>
#include <crm/pengine/rules_internal.h>

static void
run_one_test(const char *t, const char *x, int expected) {
    crm_time_t *tm = crm_time_new(t);
    xmlNodePtr xml = string2xml(x);

    g_assert_cmpint(pe_cron_range_satisfied(tm, xml), ==, expected);

    crm_time_free(tm);
    free_xml(xml);
}

static void
no_time_given(void) {
    g_assert_cmpint(pe_cron_range_satisfied(NULL, NULL), ==, pcmk_rc_op_unsatisfied);
}

static void
any_time_satisfies_empty_spec(void) {
    crm_time_t *tm = crm_time_new(NULL);

    g_assert_cmpint(pe_cron_range_satisfied(tm, NULL), ==, pcmk_rc_ok);

    crm_time_free(tm);
}

static void
time_satisfies_year_spec(void) {
    run_one_test("2020-01-01", "<date_spec id='spec' years='2020'/>", pcmk_rc_ok);
}

static void
time_after_year_spec(void) {
    run_one_test("2020-01-01", "<date_spec id='spec' years='2019'/>", pcmk_rc_after_range);
}

static void
time_satisfies_year_range(void) {
    run_one_test("2020-01-01", "<date_spec id='spec' years='2010-2030'/>", pcmk_rc_ok);
}

static void
time_before_year_range(void) {
    run_one_test("2000-01-01", "<date_spec id='spec' years='2010-2030'/>", pcmk_rc_before_range);
}

static void
time_after_year_range(void) {
    run_one_test("2020-01-01", "<date_spec id='spec' years='2010-2015'/>", pcmk_rc_after_range);
}

static void
range_without_start_year_passes(void) {
    run_one_test("2010-01-01", "<date_spec id='spec' years='-2020'/>", pcmk_rc_ok);
}

static void
range_without_end_year_passes(void) {
    run_one_test("2010-01-01", "<date_spec id='spec' years='2000-'/>", pcmk_rc_ok);
    run_one_test("2000-10-01", "<date_spec id='spec' years='2000-'/>", pcmk_rc_ok);
}

static void
yeardays_satisfies(void) {
    run_one_test("2020-01-30", "<date_spec id='spec' yeardays='30'/>", pcmk_rc_ok);
}

static void
time_after_yeardays_spec(void) {
    run_one_test("2020-02-15", "<date_spec id='spec' yeardays='40'/>", pcmk_rc_after_range);
}

static void
yeardays_feb_29_satisfies(void) {
    run_one_test("2016-02-29", "<date_spec id='spec' yeardays='60'/>", pcmk_rc_ok);
}

static void
exact_ymd_satisfies(void) {
    run_one_test("2001-12-31", "<date_spec id='spec' years='2001' months='12' monthdays='31'/>", pcmk_rc_ok);
}

static void
range_in_month_satisfies(void) {
    run_one_test("2001-06-10", "<date_spec id='spec' years='2001' months='6' monthdays='1-10'/>", pcmk_rc_ok);
}

static void
exact_ymd_after_range(void) {
    run_one_test("2001-12-31", "<date_spec id='spec' years='2001' months='12' monthdays='30'/>", pcmk_rc_after_range);
}

static void
time_after_monthdays_range(void) {
    run_one_test("2001-06-10", "<date_spec id='spec' years='2001' months='6' monthdays='11-15'/>", pcmk_rc_before_range);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/pengine/rules/cron_range/no_time_given", no_time_given);
    g_test_add_func("/pengine/rules/cron_range/empty_spec", any_time_satisfies_empty_spec);
    g_test_add_func("/pengine/rules/cron_range/year/time_satisfies", time_satisfies_year_spec);
    g_test_add_func("/pengine/rules/cron_range/year/time_after", time_after_year_spec);
    g_test_add_func("/pengine/rules/cron_range/range/time_satisfies_year", time_satisfies_year_range);
    g_test_add_func("/pengine/rules/cron_range/range/time_before_year", time_before_year_range);
    g_test_add_func("/pengine/rules/cron_range/range/time_after_year", time_after_year_range);
    g_test_add_func("/pengine/rules/cron_range/range/no_start_year_passes", range_without_start_year_passes);
    g_test_add_func("/pengine/rules/cron_range/range/no_end_year_passes", range_without_end_year_passes);

    g_test_add_func("/pengine/rules/cron_range/yeardays/satisfies", yeardays_satisfies);
    g_test_add_func("/pengine/rules/cron_range/yeardays/time_after", time_after_yeardays_spec);
    g_test_add_func("/pengine/rules/cron_range/yeardays/feb_29_sasitfies", yeardays_feb_29_satisfies);

    g_test_add_func("/pengine/rules/cron_range/exact/ymd_satisfies", exact_ymd_satisfies);
    g_test_add_func("/pengine/rules/cron_range/range/in_month_satisfies", range_in_month_satisfies);
    g_test_add_func("/pengine/rules/cron_range/exact/ymd_after_range", exact_ymd_after_range);
    g_test_add_func("/pengine/rules/cron_range/range/in_month_after", time_after_monthdays_range);
    return g_test_run();
}
