/*
 * Copyright 2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PE_STATUS_PRIVATE__H
#  define PE_STATUS_PRIVATE__H

/* This header is for the sole use of libpe_status, so that functions can be
 * declared with G_GNUC_INTERNAL for efficiency.
 */

G_GNUC_INTERNAL
pe_resource_t *pe__create_clone_child(pe_resource_t *rsc,
                                      pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pe__force_anon(const char *standard, pe_resource_t *rsc, const char *rid,
                    pe_working_set_t *data_set);

#endif  // PE_STATUS_PRIVATE__H
