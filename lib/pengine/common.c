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

enum rsc_role_e
text2role(const char *role)
{
    return pcmk_parse_role(role);
}

const char *
task2text(enum action_tasks task)
{
    return pcmk_action_text(task);
}

enum action_tasks
text2task(const char *task)
{
    return pcmk_parse_action(task);
}

const char *
pe_pref(GHashTable * options, const char *name)
{
    return pcmk__cluster_option(options, name);
}

const char *
fail2text(enum action_fail_response fail)
{
    return pcmk_on_fail_text(fail);
}

// LCOV_EXCL_STOP
// End deprecated API
