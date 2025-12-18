/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
invalid_params(void **state)
{
    /* This is basically just here to make sure that calling
     * pcmk__unregister_formats with formatters set to NULL doesn't segfault
     */
    pcmk__unregister_formats();
    assert_null(pcmk__output_formatters());
}

static void
non_null_formatters(void **state)
{
    pcmk__register_format(NULL, "fake", pcmk__output_setup_dummy1, NULL);

    pcmk__unregister_formats();
    assert_null(pcmk__output_formatters());
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(invalid_params),
                cmocka_unit_test(non_null_formatters))
