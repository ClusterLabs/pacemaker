/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/scheduler.h>
#include <crm/common/scheduler_internal.h>

/*!
 * \brief Get readable description of a multiply-active recovery type
 *
 * \param[in] recovery  Recovery type
 *
 * \return Static string describing \p recovery
 */
const char *
pcmk_multiply_active_text(enum rsc_recovery_type recovery)
{
    switch (recovery) {
        case pcmk_multiply_active_stop:
            return "shutting it down";
        case pcmk_multiply_active_restart:
            return "attempting recovery";
        case pcmk_multiply_active_block:
            return "waiting for an administrator";
        case pcmk_multiply_active_unexpected:
            return "stopping unexpected instances";
    }
    return "Unknown";
}
