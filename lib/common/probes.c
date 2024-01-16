/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>           // pcmk__str_eq(), etc.

#include <stdio.h>                  // NULL
#include <stdbool.h>                // bool, true, false
#include <glib.h>                   // guint
#include <libxml/tree.h>            // xmlNode

#include <crm/common/options.h>     // PCMK_META_INTERVAL
#include <crm/common/xml.h>         // PCMK_XA_OPERATION

/*!
 * \brief Check whether an action name and interval represent a probe
 *
 * \param[in] task         Action name
 * \param[in] interval_ms  Action interval in milliseconds
 *
 * \return true if \p task is \c PCMK_ACTION_MONITOR and \p interval_ms is 0,
 *         otherwise false
 */
bool
pcmk_is_probe(const char *task, guint interval_ms)
{
    // @COMPAT This should be made inline at an API compatibility break
    return (interval_ms == 0)
           && pcmk__str_eq(task, PCMK_ACTION_MONITOR, pcmk__str_none);
}

/*!
 * \brief Check whether an action history entry represents a probe
 *
 * \param[in] xml  XML of action history entry
 *
 * \return true if \p xml is for a probe action, otherwise false
 */
bool
pcmk_xe_is_probe(const xmlNode *xml)
{
    int interval_ms = 0;

    if (xml == NULL) {
        return false;
    }

    pcmk__scan_min_int(crm_element_value(xml, PCMK_META_INTERVAL),
                       &interval_ms, 0);

    return pcmk_is_probe(crm_element_value(xml, PCMK_XA_OPERATION),
                         interval_ms);
}

/*!
 * \brief Check whether an action history entry represents a maskable probe
 *
 * \param[in] xml  XML of action history entry
 *
 * \return true if \p xml is for a failed probe action that should be treated as
 *         successful, otherwise false
 */
bool
pcmk_xe_mask_probe_failure(const xmlNode *xml)
{
    int exec_status = PCMK_EXEC_UNKNOWN;
    int exit_status = PCMK_OCF_OK;

    if (!pcmk_xe_is_probe(xml)) {
        return false;
    }

    crm_element_value_int(xml, PCMK__XA_OP_STATUS, &exec_status);
    crm_element_value_int(xml, PCMK__XA_RC_CODE, &exit_status);

    return (exit_status == PCMK_OCF_NOT_INSTALLED)
           || (exit_status == PCMK_OCF_INVALID_PARAM)
           || (exec_status == PCMK_EXEC_NOT_INSTALLED);
}
