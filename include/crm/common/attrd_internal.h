/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__ATTRD_INTERNAL__H
#  define PCMK__ATTRD_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

// Options for clients to use with functions below
enum pcmk__node_attr_opts {
    pcmk__node_attr_none    = 0,
    pcmk__node_attr_remote  = (1 << 0),
    pcmk__node_attr_private = (1 << 1),
    pcmk__node_attr_pattern = (1 << 2),
    pcmk__node_attr_value   = (1 << 3),
    pcmk__node_attr_delay   = (1 << 4),
    pcmk__node_attr_perm    = (1 << 5),
};

#define pcmk__set_node_attr_flags(node_attr_flags, flags_to_set) do {   \
        node_attr_flags = pcmk__set_flags_as(__func__, __LINE__,        \
            LOG_TRACE, "Node attribute", crm_system_name,               \
            (node_attr_flags), (flags_to_set), #flags_to_set);          \
    } while (0)

#define pcmk__clear_node_attr_flags(node_attr_flags, flags_to_clear) do {   \
        node_attr_flags = pcmk__clear_flags_as(__func__, __LINE__,          \
            LOG_TRACE, "Node attribute", crm_system_name,                   \
            (node_attr_flags), (flags_to_clear), #flags_to_clear);          \
    } while (0)

const char *pcmk__node_attr_target(const char *name);

#ifdef __cplusplus
}
#endif

#endif
