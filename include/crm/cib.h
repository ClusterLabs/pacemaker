/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CIB__H
#define PCMK__CRM_CIB__H

#include <glib.h>               // gboolean

// cib.h is a wrapper for the following headers
#include <crm/cib/cib_types.h>
#include <crm/cib/util.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Cluster Configuration
 * \ingroup cib
 */

// Use pcmk__compare_versions() for doing comparisons
#define CIB_FEATURE_SET "2.0"

/* Core functions */

// NOTE: sbd (as of at least 1.5.2) uses this
cib_t *cib_new(void);

cib_t *cib_native_new(void);
cib_t *cib_file_new(const char *filename);
cib_t *cib_remote_new(const char *server, const char *user, const char *passwd, int port,
                      gboolean encrypted);

char *get_shadow_file(const char *name);
cib_t *cib_shadow_new(const char *name);

void cib_free_notify(cib_t *cib);
void cib_free_callbacks(cib_t *cib);

// NOTE: sbd (as of at least 1.5.2) uses this
void cib_delete(cib_t *cib);

void cib_dump_pending_callbacks(void);
int num_cib_op_callbacks(void);
void remove_cib_op_callback(int call_id, gboolean all_callbacks);

#define CIB_LIBRARY "libcib.so.54"

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/cib_compat.h>
#endif

#endif  // PCMK__CRM_CIB__H
