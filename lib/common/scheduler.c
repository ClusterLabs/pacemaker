/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>               // gboolean
#include <stdint.h>             // uint32_t

uint32_t pcmk__warnings = 0;

gboolean was_processing_error = FALSE;
gboolean was_processing_warning = FALSE;
