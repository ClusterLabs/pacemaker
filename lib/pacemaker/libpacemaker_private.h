/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__LIBPACEMAKER_PRIVATE__H
#  define PCMK__LIBPACEMAKER_PRIVATE__H

/* This header is for the sole use of libpacemaker, so that functions can be
 * declared with G_GNUC_INTERNAL for efficiency.
 */

#include <crm/pengine/pe_types.h> // pe_action_t, pe_node_t, pe_working_set_t

G_GNUC_INTERNAL
void pcmk__order_vs_fence(pe_action_t *stonith_op, pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__fence_guest(pe_node_t *node, pe_working_set_t *data_set);

G_GNUC_INTERNAL
bool pcmk__node_unfenced(pe_node_t *node);

G_GNUC_INTERNAL
bool pcmk__is_unfence_device(const pe_resource_t *rsc,
                             const pe_working_set_t *data_set);

#endif // PCMK__LIBPACEMAKER_PRIVATE__H
