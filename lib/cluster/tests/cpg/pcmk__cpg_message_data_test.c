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

#include <qb/qbipc_common.h>                // struct qb_ipc_response_header

/* These mirror the layout of the private pcmk__cpg_host_t and pcmk__cpg_msg_t
 * in lib/cluster/cpg.c. That struct is frozen for rolling-upgrade
 * compatibility, so duplicating it here is stable. It only needs to be
 * byte-compatible so we can craft a message buffer to feed to
 * pcmk__cpg_message_data().
 */
struct test_cpg_host {
    uint32_t id;
    uint32_t pid;
    gboolean local;
    enum pcmk_ipc_server type;
    uint32_t size;
    char uname[MAX_NAME];
} __attribute__ ((packed));

struct test_cpg_msg {
    struct qb_ipc_response_header header __attribute__ ((aligned(8)));
    uint32_t id;
    gboolean is_compressed;
    struct test_cpg_host host;
    struct test_cpg_host sender;
    uint32_t size;
    uint32_t compressed_size;
    char data[0];
} __attribute__ ((packed));

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
    size_t len = sizeof(struct test_cpg_msg);
    struct test_cpg_msg *msg = pcmk__assert_alloc(1, len);
    const char *from = NULL;

    msg->header.size = len + 100;
    assert_null(pcmk__cpg_message_data(0, 1, 1, msg, len, &from));
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
    size_t len = sizeof(struct test_cpg_msg) + 2;
    struct test_cpg_msg *msg = pcmk__assert_alloc(1, len);
    const char *from = NULL;
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

    data = pcmk__cpg_message_data(0, 2, 1, msg, len, &from);
    assert_string_equal(data, "x");

    free(data);
    free(msg);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(message_too_short),
                cmocka_unit_test(claimed_size_too_large),
                cmocka_unit_test(unterminated_sender_uname))
#else
PCMK__UNIT_TEST(NULL, NULL)
#endif  // SUPPORT_COROSYNC
