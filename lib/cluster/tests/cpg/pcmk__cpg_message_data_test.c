/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>                         // uint32_t
#include <string.h>                         // memset, memcpy
#include <sys/types.h>                      // size_t

#include <crm/cluster.h>                    // pcmk_cluster_t, etc.
#include <crm/cluster/internal.h>           // pcmk__cpg_message_data
#include <crm/common/unittest_internal.h>

#if SUPPORT_COROSYNC

#include "crmcluster_private.h"             // pcmk__cpg_msg_t

static int
setup(void **state)
{
    pcmk__cluster_init_node_caches();
    return 0;
}

static int
teardown(void **state)
{
    pcmk__cluster_destroy_node_caches();
    return 0;
}

// A message smaller than the fixed header is rejected without dereferencing it
static void
message_too_short(void **state)
{
    char buf[4] = { 0, };
    const char *from = NULL;

    assert_null(pcmk__cpg_message_data(0, 1, 1, buf, sizeof(buf), &from));
    assert_null(from);
}

// A message whose claimed size exceeds what was delivered is rejected
static void
claimed_size_too_large(void **state)
{
    size_t len = sizeof(pcmk__cpg_msg_t);
    pcmk__cpg_msg_t *msg = pcmk__assert_alloc(1, len);

    msg->header.size = len + 100;
    assert_null(pcmk__cpg_message_data(0, 1, 1, msg, len, NULL));
    free(msg);
}

/* An otherwise valid message whose claimed size is less than what was delivered
 * is rejected
 */
static void
claimed_size_too_small(void **state)
{
    size_t len = sizeof(pcmk__cpg_msg_t) + 2 + 100;
    pcmk__cpg_msg_t *msg = pcmk__assert_alloc(1, len);

    msg->header.size = sizeof(pcmk__cpg_msg_t) + 2;
    msg->header.error = CS_OK;
    msg->size = 2;
    msg->data[0] = 'x';
    msg->data[1] = '\0';

    assert_null(pcmk__cpg_message_data(0, 1, 1, msg, len, NULL));
    free(msg);
}

/* A well-sized message whose sender uname fills the whole field with no null
 * terminator must not be read past the end of the field. Before the fix, this
 * caused a heap-buffer-overflow read (confirmed with ASan) when the name was
 * copied in pcmk__get_node().
 */
static void
unterminated_sender_uname(void **state)
{
    size_t len = sizeof(pcmk__cpg_msg_t) + 2;
    pcmk__cpg_msg_t *msg = pcmk__assert_alloc(1, len);
    char *data = NULL;

    msg->header.size = len;
    msg->header.error = CS_OK;
    msg->sender.id = 2;
    msg->is_compressed = FALSE;
    msg->size = 2;

    // Fill the entire sender uname field with non-null bytes (no terminator)
    memset(msg->sender.uname, 'a', sizeof(msg->sender.uname));

    msg->data[0] = 'x';
    msg->data[1] = '\0';

    data = pcmk__cpg_message_data(0, 2, 1, msg, len, NULL);
    assert_string_equal(data, "x");

    free(data);
    free(msg);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(message_too_short),
                cmocka_unit_test(claimed_size_too_large),
                cmocka_unit_test(claimed_size_too_small),
                cmocka_unit_test(unterminated_sender_uname))
#else
PCMK__UNIT_TEST(NULL, NULL)
#endif  // SUPPORT_COROSYNC
