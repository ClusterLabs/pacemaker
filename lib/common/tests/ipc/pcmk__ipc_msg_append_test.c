/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                      // EBADMSG, EINVAL
#include <stdint.h>                     // uint16_t, uint32_t
#include <string.h>                     // memcpy, strlen

#include <glib.h>                       // GByteArray, guint8, guint

#include <crm/common/unittest_internal.h>
#include "../../crmcommon_private.h"

#define PAYLOAD "<ping/>"

/* Build a message the way libqb hands it to a dispatch function: the header
 * followed by exactly qb.size - sizeof(header) bytes
 */
static guint8 *
new_message(uint32_t flags, uint16_t part_id)
{
    size_t payload_size = strlen(PAYLOAD) + 1;
    guint8 *data = pcmk__assert_alloc(1, sizeof(pcmk__ipc_header_t)
                                         + payload_size);
    pcmk__ipc_header_t *header = (void *) data;

    header->qb.id = 1;
    header->qb.size = sizeof(pcmk__ipc_header_t) + payload_size;
    header->version = PCMK__IPC_VERSION;
    header->size = payload_size;
    header->flags = flags;
    header->part_id = part_id;
    memcpy(data + sizeof(pcmk__ipc_header_t), PAYLOAD, payload_size);
    return data;
}

static void
null_header(void **state)
{
    assert_false(pcmk__valid_ipc_header(NULL));
}

static void
valid_message(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *data = new_message(0, 0);
    pcmk__ipc_header_t *full_header = NULL;

    assert_int_equal(pcmk__ipc_msg_append(&buffer, data), pcmk_rc_ok);
    assert_non_null(buffer);
    assert_string_equal((const char *) buffer->data
                        + sizeof(pcmk__ipc_header_t), PAYLOAD);

    full_header = (void *) buffer->data;
    assert_int_equal(full_header->size, strlen(PAYLOAD) + 1);

    g_byte_array_free(buffer, TRUE);
    free(data);
}

static void
unterminated_message(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *data = new_message(0, 0);
    pcmk__ipc_header_t *header = (void *) data;
    pcmk__ipc_header_t *full_header = NULL;

    // Replace the null terminator with another character
    data[sizeof(pcmk__ipc_header_t) + header->size - 1] = 'x';

    assert_int_equal(pcmk__ipc_msg_append(&buffer, data), pcmk_rc_ok);
    assert_non_null(buffer);
    assert_int_equal(buffer->len,
                     sizeof(pcmk__ipc_header_t) + strlen(PAYLOAD) + 2);
    assert_string_equal((const char *) buffer->data
                        + sizeof(pcmk__ipc_header_t), PAYLOAD "x");

    full_header = (void *) buffer->data;
    assert_int_equal(full_header->size, strlen(PAYLOAD) + 2);

    g_byte_array_free(buffer, TRUE);
    free(data);
}

static void
bad_version(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *data = new_message(0, 0);
    pcmk__ipc_header_t *header = (void *) data;

    header->version = PCMK__IPC_VERSION + 1;
    assert_int_equal(pcmk__ipc_msg_append(&buffer, data), EBADMSG);
    assert_null(buffer);

    free(data);
}

static void
payload_size_too_large(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *data = new_message(0, 0);
    pcmk__ipc_header_t *header = (void *) data;

    header->size += 4096;
    assert_int_equal(pcmk__ipc_msg_append(&buffer, data), EBADMSG);
    assert_null(buffer);

    free(data);
}

static void
message_size_too_small(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *data = new_message(0, 0);
    pcmk__ipc_header_t *header = (void *) data;

    header->qb.size = sizeof(pcmk__ipc_header_t) - 1;
    assert_int_equal(pcmk__ipc_msg_append(&buffer, data), EBADMSG);
    assert_null(buffer);

    // A message with only a header has no payload
    header->size = 0;
    header->qb.size = sizeof(pcmk__ipc_header_t);
    assert_int_equal(pcmk__ipc_msg_append(&buffer, data), EBADMSG);
    assert_null(buffer);

    free(data);
}

static void
standalone_bad_buffer(void **state)
{
    GByteArray *buffer = g_byte_array_new();
    guint8 *data = new_message(0, 0);

    assert_int_equal(pcmk__ipc_msg_append(NULL, data), EINVAL);
    assert_int_equal(pcmk__ipc_msg_append(&buffer, data), EINVAL);
    assert_int_equal(buffer->len, 0);

    g_byte_array_free(buffer, TRUE);
    free(data);
}

static void
multipart_message(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *first = new_message(crm_ipc_multipart, 0);
    guint8 *next = new_message(crm_ipc_multipart, 1);
    guint8 *last = new_message(crm_ipc_multipart_end, 2);
    pcmk__ipc_header_t *full_header = NULL;

    assert_int_equal(pcmk__ipc_msg_append(&buffer, first), pcmk_rc_ipc_more);
    assert_int_equal(pcmk__ipc_msg_append(&buffer, next), pcmk_rc_ipc_more);
    assert_int_equal(pcmk__ipc_msg_append(&buffer, last), pcmk_rc_ok);
    assert_string_equal((const char *) buffer->data
                        + sizeof(pcmk__ipc_header_t),
                        PAYLOAD PAYLOAD PAYLOAD);

    full_header = (void *) buffer->data;
    assert_int_equal(full_header->size, (3 * strlen(PAYLOAD)) + 1);
    assert_false(pcmk__is_set(full_header->flags, crm_ipc_multipart));

    g_byte_array_free(buffer, TRUE);
    free(first);
    free(next);
    free(last);
}

static void
multipart_first_bad_buffer(void **state)
{
    GByteArray *buffer = g_byte_array_new();
    guint8 *first = new_message(crm_ipc_multipart, 0);

    assert_int_equal(pcmk__ipc_msg_append(NULL, first), EINVAL);
    assert_int_equal(pcmk__ipc_msg_append(&buffer, first), EINVAL);
    assert_int_equal(buffer->len, 0);

    g_byte_array_free(buffer, TRUE);
    free(first);
}

static void
multipart_next_bad_buffer(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *next = new_message(crm_ipc_multipart, 1);

    assert_int_equal(pcmk__ipc_msg_append(NULL, next), EINVAL);
    assert_int_equal(pcmk__ipc_msg_append(&buffer, next), EINVAL);
    assert_null(buffer);

    free(next);
}

static void
multipart_next_wrong_id(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *first = new_message(crm_ipc_multipart, 0);
    guint8 *next = new_message(crm_ipc_multipart, 1);
    pcmk__ipc_header_t *header = (void *) next;
    guint len = 0;

    assert_int_equal(pcmk__ipc_msg_append(&buffer, first), pcmk_rc_ipc_more);
    len = buffer->len;

    header->qb.id++;
    assert_int_equal(pcmk__ipc_msg_append(&buffer, next), EBADMSG);
    assert_int_equal(buffer->len, len);

    g_byte_array_free(buffer, TRUE);
    free(first);
    free(next);
}

static void
multipart_empty_part(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *first = new_message(crm_ipc_multipart, 0);
    guint8 *next = new_message(crm_ipc_multipart, 1);
    pcmk__ipc_header_t *header = (void *) next;

    assert_int_equal(pcmk__ipc_msg_append(&buffer, first), pcmk_rc_ipc_more);
    assert_non_null(buffer);

    header->size = 0;
    header->qb.size = sizeof(pcmk__ipc_header_t);
    assert_int_equal(pcmk__ipc_msg_append(&buffer, next), EBADMSG);

    g_byte_array_free(buffer, TRUE);
    free(first);
    free(next);
}

static void
multipart_end_bad_buffer(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *last = new_message(crm_ipc_multipart_end, 1);

    assert_int_equal(pcmk__ipc_msg_append(NULL, last), EINVAL);
    assert_int_equal(pcmk__ipc_msg_append(&buffer, last), EINVAL);
    assert_null(buffer);

    free(last);
}

static void
multipart_end_part_zero(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *first = new_message(crm_ipc_multipart, 0);
    guint8 *last = new_message(crm_ipc_multipart_end, 0);
    guint len = 0;

    assert_int_equal(pcmk__ipc_msg_append(&buffer, first), pcmk_rc_ipc_more);
    len = buffer->len;

    assert_int_equal(pcmk__ipc_msg_append(&buffer, last), EINVAL);
    assert_int_equal(buffer->len, len);

    g_byte_array_free(buffer, TRUE);
    free(first);
    free(last);
}

static void
multipart_end_wrong_id(void **state)
{
    GByteArray *buffer = NULL;
    guint8 *first = new_message(crm_ipc_multipart, 0);
    guint8 *last = new_message(crm_ipc_multipart_end, 1);
    pcmk__ipc_header_t *header = (void *) last;
    guint len = 0;

    assert_int_equal(pcmk__ipc_msg_append(&buffer, first), pcmk_rc_ipc_more);
    len = buffer->len;

    header->qb.id++;
    assert_int_equal(pcmk__ipc_msg_append(&buffer, last), EBADMSG);
    assert_int_equal(buffer->len, len);

    g_byte_array_free(buffer, TRUE);
    free(first);
    free(last);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_header),
                cmocka_unit_test(valid_message),
                cmocka_unit_test(unterminated_message),
                cmocka_unit_test(bad_version),
                cmocka_unit_test(payload_size_too_large),
                cmocka_unit_test(message_size_too_small),
                cmocka_unit_test(standalone_bad_buffer),
                cmocka_unit_test(multipart_message),
                cmocka_unit_test(multipart_first_bad_buffer),
                cmocka_unit_test(multipart_next_bad_buffer),
                cmocka_unit_test(multipart_next_wrong_id),
                cmocka_unit_test(multipart_empty_part),
                cmocka_unit_test(multipart_end_bad_buffer),
                cmocka_unit_test(multipart_end_part_zero),
                cmocka_unit_test(multipart_end_wrong_id))
