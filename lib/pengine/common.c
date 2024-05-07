/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>

#include <glib.h>

#include <crm/common/scheduler_internal.h>
#include <crm/pengine/internal.h>

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/pengine/common_compat.h>

const char *
role2text(enum rsc_role_e role)
{
    return pcmk_role_text(role);
}

// LCOV_EXCL_STOP
// End deprecated API
