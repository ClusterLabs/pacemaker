/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>             // uint32_t
#include <errno.h>              // EINVAL
#include <glib.h>               // gboolean, FALSE
#include <libxml/tree.h>        // xmlNode

#include <crm/common/scheduler.h>

uint32_t pcmk__warnings = 0;

gboolean was_processing_error = FALSE;
gboolean was_processing_warning = FALSE;

/*!
 * \internal
 * \brief Set CIB XML as scheduler input in scheduler data
 *
 * \param[out] scheduler  Scheduler data
 * \param[in]  cib        CIB XML to set as scheduler input
 *
 * \return Standard Pacemaker return code (EINVAL if \p scheduler is NULL,
 *         otherwise pcmk_rc_ok)
 * \note This will not free any previously set scheduler CIB.
 */
int
pcmk_set_scheduler_cib(pcmk_scheduler_t *scheduler, xmlNode *cib)
{
    if (scheduler == NULL) {
        return EINVAL;
    }
    scheduler->input = cib;
    return pcmk_rc_ok;
}
