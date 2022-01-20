/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CIB__H
#  define PCMK__CRM_CIB__H

#  include <glib.h>             // gboolean
#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>
#  include <crm/cib/cib_types.h>
#  include <crm/cib/util.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Cluster Configuration
 * \ingroup cib
 */

#  define CIB_FEATURE_SET "2.0"

/* use compare_version() for doing comparisons */

#define T_CIB_DIFF_NOTIFY	"cib_diff_notify"

/* Core functions */
cib_t *cib_new(void);
cib_t *cib_native_new(void);
cib_t *cib_file_new(const char *filename);
cib_t *cib_remote_new(const char *server, const char *user, const char *passwd, int port,
                      gboolean encrypted);

cib_t *cib_new_no_shadow(void);
char *get_shadow_file(const char *name);
cib_t *cib_shadow_new(const char *name);

void cib_free_notify(cib_t *cib);
void cib_free_callbacks(cib_t *cib);
void cib_delete(cib_t * cib);

void cib_dump_pending_callbacks(void);
int num_cib_op_callbacks(void);
void remove_cib_op_callback(int call_id, gboolean all_callbacks);

#  define CIB_LIBRARY "libcib.so.27"

#ifdef __cplusplus
}
#endif

#endif
