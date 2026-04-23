/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/unittest_internal.h>

#include "mock_private.h"

static void
empty_formatters(void **state)
{
    GHashTable *formatters = pcmk__output_formatters();
    pcmk__output_t *out = NULL;

    pcmk__set_output_formatters(NULL);
    pcmk__assert_asserts(pcmk__output_new(&out, "fake", NULL, NULL));
    pcmk__set_output_formatters(formatters);
}

static void
invalid_params(void **state)
{
    /* This must be called with the setup/teardown functions so that formatters
     * is not NULL
     */
    pcmk__assert_asserts(pcmk__output_new(NULL, "fake", NULL, NULL));
}

static void
no_such_format(void **state)
{
    pcmk__output_t *out = NULL;

    assert_int_equal(pcmk__output_new(&out, "fake", NULL, NULL),
                     pcmk_rc_unknown_format);
}

static void
create_fails(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__mock_calloc = true;   // calloc() will return NULL

    expect_uint_value(__wrap_calloc, nmemb, 1);
    expect_uint_value(__wrap_calloc, size, sizeof(pcmk__output_t));
    assert_int_equal(pcmk__output_new(&out, "text", NULL, NULL), ENOMEM);

    pcmk__mock_calloc = false;  // Use real calloc()
}

static void
fopen_fails(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__mock_fopen = true;
#if defined(HAVE_FOPEN64) && defined(_FILE_OFFSET_BITS) \
    && (_FILE_OFFSET_BITS == 64) && (SIZEOF_LONG < 8)
    expect_string(__wrap_fopen64, pathname, "destfile");
    expect_string(__wrap_fopen64, mode, "w");
    will_return(__wrap_fopen64, EPERM);
#else
    expect_string(__wrap_fopen, pathname, "destfile");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, EPERM);
#endif

    assert_int_equal(pcmk__output_new(&out, "text", "destfile", NULL), EPERM);

    pcmk__mock_fopen = false;
}

static void
init_fails(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__set_fake_text_init_succeeds(false);
    assert_int_equal(pcmk__output_new(&out, "text", NULL, NULL), ENOMEM);
    pcmk__set_fake_text_init_succeeds(true);
}

static void
everything_succeeds(void **state)
{
    pcmk__output_t *out = NULL;

    assert_int_equal(pcmk__output_new(&out, "text", NULL, NULL), pcmk_rc_ok);
    assert_string_equal(out->fmt_name, "text");
    assert_ptr_equal(out->dest, stdout);
    assert_false(out->quiet);
    assert_non_null(out->messages);
    assert_string_equal(getenv("OCF_OUTPUT_FORMAT"), "text");

    pcmk__output_free(out);
}

static void
no_fmt_name_given(void **state)
{
    pcmk__output_t *out = NULL;

    // "text" is the default format for pcmk__output_new()
    assert_int_equal(pcmk__output_new(&out, NULL, NULL, NULL), pcmk_rc_ok);
    assert_string_equal(out->fmt_name, "text");

    pcmk__output_free(out);
}

PCMK__UNIT_TEST(pcmk__output_test_setup_group, pcmk__output_test_teardown_group,
                cmocka_unit_test(empty_formatters),
                cmocka_unit_test(invalid_params),
                cmocka_unit_test(no_such_format),
                cmocka_unit_test(create_fails),
                cmocka_unit_test(init_fails),
                cmocka_unit_test(fopen_fails),
                cmocka_unit_test(everything_succeeds),
                cmocka_unit_test(no_fmt_name_given))
