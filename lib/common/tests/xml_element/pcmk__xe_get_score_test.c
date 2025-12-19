/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <limits.h>

#include <crm/common/scores.h>
#include <crm/common/unittest_internal.h>

#define ATTR_NAME "test_attr"

static int default_score = 99;

#define assert_score(score_s, expected_rc, expected_score)              \
    do {                                                                \
        int rc = pcmk_rc_ok;                                            \
        int score = 0;                                                  \
        xmlNode *xml = pcmk__xe_create(NULL, __func__);                 \
                                                                        \
        pcmk__xe_set(xml, ATTR_NAME, score_s);                          \
                                                                        \
        rc = pcmk__xe_get_score(xml, ATTR_NAME, &score, default_score); \
        assert_int_equal(rc, expected_rc);                              \
        assert_int_equal(score, expected_score);                        \
        pcmk__xml_free(xml);                                            \
    } while (0)

static void
invalid_args(void **state)
{
    int score = 0;
    xmlNode *xml = pcmk__xe_create(NULL, __func__);

    assert_int_equal(pcmk__xe_get_score(NULL, NULL, &score, default_score),
                     EINVAL);
    assert_int_equal(pcmk__xe_get_score(xml, NULL, &score, default_score),
                     EINVAL);
    assert_int_equal(pcmk__xe_get_score(NULL, "test", &score, default_score),
                     EINVAL);
    pcmk__xml_free(xml);
}

static void
null_score_string(void **state)
{
    assert_score(NULL, pcmk_rc_ok, default_score);

    // Test out-of-bounds default score

    default_score = -2000000;
    assert_score(NULL, pcmk_rc_ok, -PCMK_SCORE_INFINITY);

    default_score = 2000000;
    assert_score(NULL, pcmk_rc_ok, PCMK_SCORE_INFINITY);

    default_score = 99;
}

static void
null_score(void **state)
{
    xmlNode *xml = pcmk__xe_create(NULL, __func__);

    assert_int_equal(pcmk__xe_get_score(xml, ATTR_NAME, NULL, default_score),
                     pcmk_rc_ok);

    pcmk__xe_set(xml, ATTR_NAME, "0");
    assert_int_equal(pcmk__xe_get_score(xml, ATTR_NAME, NULL, default_score),
                     pcmk_rc_ok);

    pcmk__xe_set(xml, ATTR_NAME, "foo");
    assert_int_equal(pcmk__xe_get_score(xml, ATTR_NAME, NULL, default_score),
                     pcmk_rc_bad_input);

    pcmk__xml_free(xml);
}

static void
bad_input(void **state)
{
    assert_score("redder", pcmk_rc_bad_input, default_score);
    assert_score("3.141592", pcmk_rc_ok, 3);
    assert_score("0xf00d", pcmk_rc_ok, 0);
}

static void
special_values(void **state)
{
    assert_score("-INFINITY", pcmk_rc_ok, -PCMK_SCORE_INFINITY);
    assert_score("INFINITY", pcmk_rc_ok, PCMK_SCORE_INFINITY);
    assert_score("+INFINITY", pcmk_rc_ok, PCMK_SCORE_INFINITY);

    pcmk__score_red = 10;
    pcmk__score_green = 20;
    pcmk__score_yellow = 30;

    assert_score("red", pcmk_rc_ok, pcmk__score_red);
    assert_score("green", pcmk_rc_ok, pcmk__score_green);
    assert_score("yellow", pcmk_rc_ok, pcmk__score_yellow);

    assert_score("ReD", pcmk_rc_ok, pcmk__score_red);
    assert_score("GrEeN", pcmk_rc_ok, pcmk__score_green);
    assert_score("yElLoW", pcmk_rc_ok, pcmk__score_yellow);
}

/* These ridiculous macros turn an integer constant into a string constant. */
#define A(x) #x
#define B(x) A(x)

static void
outside_limits(void **state)
{
    char *very_long = pcmk__assert_asprintf(" %lld0", LLONG_MAX);

    // Still within int range
    assert_score(B(PCMK_SCORE_INFINITY) "00", pcmk_rc_ok, PCMK_SCORE_INFINITY);
    assert_score("-" B(PCMK_SCORE_INFINITY) "00", pcmk_rc_ok,
                 -PCMK_SCORE_INFINITY);

    // Outside long long range
    assert_score(very_long, pcmk_rc_ok, PCMK_SCORE_INFINITY);
    very_long[0] = '-';
    assert_score(very_long, pcmk_rc_ok, -PCMK_SCORE_INFINITY);

    free(very_long);
}

static void
inside_limits(void **state)
{
    assert_score("1234", pcmk_rc_ok, 1234);
    assert_score("-1234", pcmk_rc_ok, -1234);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(invalid_args),
                cmocka_unit_test(null_score_string),
                cmocka_unit_test(null_score),
                cmocka_unit_test(bad_input),
                cmocka_unit_test(special_values),
                cmocka_unit_test(outside_limits),
                cmocka_unit_test(inside_limits))
