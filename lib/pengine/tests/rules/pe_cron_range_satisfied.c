#include <glib.h>

#include <crm/common/xml.h>
#include <crm/pengine/rules_internal.h>

static void
run_one_test(const char *t, const char *x, gboolean expected) {
    crm_time_t *tm = crm_time_new(t);
    xmlNodePtr xml = string2xml(x);

    g_assert(pe_cron_range_satisfied(tm, xml) == expected);

    crm_time_free(tm);
    xmlFreeNode(xml);
}

static void
no_time_given(void) {
    g_assert(pe_cron_range_satisfied(NULL, NULL) == FALSE);
}

static void
any_time_satisfies_empty_spec(void) {
    crm_time_t *tm = crm_time_new(NULL);

    g_assert(pe_cron_range_satisfied(tm, NULL) == TRUE);

    crm_time_free(tm);
}

static void
time_satisfies_year_spec(void) {
    run_one_test("2020-01-01", "<date_spec id='spec' years='2020'/>", TRUE);
}

static void
time_doesnt_satisfy_year_spec(void) {
    run_one_test("2020-01-01", "<date_spec id='spec' years='2019'/>", FALSE);
}

static void
time_satisfies_year_range(void) {
    run_one_test("2020-01-01", "<date_spec id='spec' years='2010-2030'/>", TRUE);
}

static void
time_before_year_range(void) {
    run_one_test("2000-01-01", "<date_spec id='spec' years='2010-2030'/>", FALSE);
}

static void
time_after_year_range(void) {
    run_one_test("2020-01-01", "<date_spec id='spec' years='2010-2015'/>", FALSE);
}

static void
range_without_start_year_fails(void) {
    run_one_test("2010-01-01", "<date_spec id='spec' years='-2020'/>", FALSE);
}

static void
range_without_end_year_fails(void) {
    run_one_test("2010-01-01", "<date_spec id='spec' years='2000-'/>", FALSE);
}

static void
range_without_end_year_passes(void) {
    run_one_test("2000-10-01", "<date_spec id='spec' years='2000-'/>", TRUE);
}

static void
yeardays_satisfies(void) {
    run_one_test("2020-01-30", "<date_spec id='spec' yeardays='30'/>", TRUE);
}

static void
yeardays_doesnt_satisfy(void) {
    run_one_test("2020-02-15", "<date_spec id='spec' yeardays='40'/>", FALSE);
}

static void
yeardays_feb_29_satisfies(void) {
    run_one_test("2016-02-29", "<date_spec id='spec' yeardays='60'/>", TRUE);
}

static void
exact_ymd_satisfies(void) {
    run_one_test("2001-12-31", "<date_spec id='spec' years='2001' months='12' monthdays='31'/>", TRUE);
}

static void
range_in_month_satisfies(void) {
    run_one_test("2001-06-10", "<date_spec id='spec' years='2001' months='6' monthdays='1-10'/>", TRUE);
}

static void
exact_ymd_doesnt_satisfy(void) {
    run_one_test("2001-12-31", "<date_spec id='spec' years='2001' months='12' monthdays='30'/>", FALSE);
}

static void
range_in_month_doesnt_satisfy(void) {
    run_one_test("2001-06-10", "<date_spec id='spec' years='2001' months='6' monthdays='11-15'/>", FALSE);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/pengine/rules/cron_range/no_time_given", no_time_given);
    g_test_add_func("/pengine/rules/cron_range/empty_spec", any_time_satisfies_empty_spec);
    g_test_add_func("/pengine/rules/cron_range/year/time_satisfies", time_satisfies_year_spec);
    g_test_add_func("/pengine/rules/cron_range/year/time_doesnt_satisfy", time_doesnt_satisfy_year_spec);
    g_test_add_func("/pengine/rules/cron_range/range/time_satisfies_year", time_satisfies_year_range);
    g_test_add_func("/pengine/rules/cron_range/range/time_before_year", time_before_year_range);
    g_test_add_func("/pengine/rules/cron_range/range/time_after_year", time_after_year_range);
    g_test_add_func("/pengine/rules/cron_range/range/no_start_year_fails", range_without_start_year_fails);
    g_test_add_func("/pengine/rules/cron_range/range/no_end_year_fails", range_without_end_year_fails);
    g_test_add_func("/pengine/rules/cron_range/range/no_end_year_passes", range_without_end_year_passes);

    g_test_add_func("/pengine/rules/cron_range/yeardays/satisfies", yeardays_satisfies);
    g_test_add_func("/pengine/rules/cron_range/yeardays/doesnt_satisfy", yeardays_doesnt_satisfy);
    g_test_add_func("/pengine/rules/cron_range/yeardays/feb_29_sasitfies", yeardays_feb_29_satisfies);

    g_test_add_func("/pengine/rules/cron_range/exact/ymd_satisfies", exact_ymd_satisfies);
    g_test_add_func("/pengine/rules/cron_range/range/in_month_satisfies", range_in_month_satisfies);
    g_test_add_func("/pengine/rules/cron_range/exact/ymd_doesnt_satisfy", exact_ymd_doesnt_satisfy);
    g_test_add_func("/pengine/rules/cron_range/range/in_month_doesnt_satisfy", range_in_month_doesnt_satisfy);
    return g_test_run();
}
