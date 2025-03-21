/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_STRINGS__H
#define PCMK__CRM_COMMON_STRINGS__H

#include <glib.h>                    // gboolean, guint, G_GNUC_PRINTF

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief API for strings
 * \ingroup core
 */

int pcmk_parse_interval_spec(const char *input, guint *result_ms);

// NOTE: sbd (as of at least 1.5.2) uses this
gboolean crm_is_true(const char *s);

int crm_str_to_boolean(const char *s, int *ret);

// NOTE: sbd (as of at least 1.5.2) uses this
char *crm_strdup_printf(char const *format, ...) G_GNUC_PRINTF(1, 2);

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/strings_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_STRINGS__H
