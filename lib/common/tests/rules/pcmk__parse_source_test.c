/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>

#include <crm/common/rules_internal.h>
#include <crm/common/unittest_internal.h>
#include "crmcommon_private.h"

static void
default_literal(void **state)
{
    assert_int_equal(pcmk__parse_source(NULL), pcmk__source_literal);
}

static void
invalid(void **state)
{
    assert_int_equal(pcmk__parse_source(""), pcmk__source_unknown);
    assert_int_equal(pcmk__parse_source(" "), pcmk__source_unknown);
    assert_int_equal(pcmk__parse_source("params"), pcmk__source_unknown);
}

static void
valid(void **state)
{
    assert_int_equal(pcmk__parse_source(PCMK_VALUE_LITERAL),
                     pcmk__source_literal);

    assert_int_equal(pcmk__parse_source(PCMK_VALUE_PARAM),
                     pcmk__source_instance_attrs);

    assert_int_equal(pcmk__parse_source(PCMK_VALUE_META),
                     pcmk__source_meta_attrs);
}

static void
case_insensitive(void **state)
{
    assert_int_equal(pcmk__parse_source("LITERAL"),
                     pcmk__source_literal);

    assert_int_equal(pcmk__parse_source("Param"),
                     pcmk__source_instance_attrs);

    assert_int_equal(pcmk__parse_source("MeTa"),
                     pcmk__source_meta_attrs);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(default_literal),
                cmocka_unit_test(invalid),
                cmocka_unit_test(valid),
                cmocka_unit_test(case_insensitive))
