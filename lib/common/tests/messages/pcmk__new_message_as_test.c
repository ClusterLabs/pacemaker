/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>              // NULL
#include <libxml/tree.h>        // xmlNode

#include <crm/common/ipc.h>                 // pcmk_ipc_controld
#include <crm/common/messages_internal.h>   // pcmk__new_message_as()
#include <crm/common/servers_internal.h>    // pcmk__server_message_type()
#include <crm/common/xml_internal.h>        // pcmk__xe_create(), etc.

#include <crm/common/unittest_internal.h>

static void
invalid_arguments(void **state)
{
    xmlNode *data = pcmk__xe_create(NULL, "x");

    assert_null(pcmk__new_message_as(NULL, pcmk_ipc_controld, "x", "x", "x",
                                     "x", "x", data));
    assert_null(pcmk__new_message_as("x", pcmk_ipc_controld, "x", NULL, "x",
                                     "x", "x", data));
    assert_null(pcmk__new_message_as("x", pcmk_ipc_controld, "x", "x", "x", "x",
                                     NULL, data));
    pcmk__xml_free(data);
}

static void
optional_arguments_null(void **state)
{
    xmlNode *message = NULL;

    message = pcmk__new_message_as("fn", pcmk_ipc_controld, NULL, "ss", NULL,
                                   NULL, "op", NULL);
    assert_non_null(message);
    assert_string_equal(pcmk__xe_get(message, PCMK_XA_ORIGIN), "fn");
    assert_string_equal(pcmk__xe_get(message, PCMK__XA_T),
                        pcmk__server_message_type(pcmk_ipc_controld));
    assert_string_equal(pcmk__xe_get(message, PCMK__XA_SUBT),
                        PCMK__VALUE_REQUEST);
    assert_string_equal(pcmk__xe_get(message, PCMK_XA_VERSION),
                        CRM_FEATURE_SET);
    assert_non_null(pcmk__xe_get(message, PCMK_XA_REFERENCE));
    assert_string_equal(pcmk__xe_get(message, PCMK__XA_CRM_SYS_FROM), "ss");
    assert_null(pcmk__xe_get(message, PCMK__XA_CRM_HOST_TO));
    assert_null(pcmk__xe_get(message, PCMK__XA_CRM_SYS_TO));
    assert_string_equal(pcmk__xe_get(message, PCMK__XA_CRM_TASK), "op");
    assert_null(message->children);
    pcmk__xml_free(message);
}

static void
optional_arguments_nonnull(void **state)
{
    xmlNode *message = NULL;
    xmlNode *data = pcmk__xe_create(NULL, "x");

    message = pcmk__new_message_as("fn", pcmk_ipc_controld, "rt", "ss", "node1",
                                   "rs", "op", data);
    pcmk__xml_free(data);

    assert_non_null(message);
    assert_string_equal(pcmk__xe_get(message, PCMK_XA_REFERENCE), "rt");
    assert_string_equal(pcmk__xe_get(message, PCMK__XA_CRM_HOST_TO), "node1");
    assert_string_equal(pcmk__xe_get(message, PCMK__XA_CRM_SYS_TO), "rs");
    assert_non_null(message->children);
    assert_null(message->children->next);
    assert_string_equal((const char *) (message->children->name),
                        PCMK__XE_CRM_XML);
    assert_non_null(message->children->children);
    assert_null(message->children->children->next);
    assert_string_equal((const char *) (message->children->children->name),
                        "x");
    pcmk__xml_free(message);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(invalid_arguments),
                cmocka_unit_test(optional_arguments_null),
                cmocka_unit_test(optional_arguments_nonnull))
