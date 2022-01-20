/*
 * Copyright 2009-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_MAINLOOP_COMPAT__H
#  define PCMK__CRM_COMMON_MAINLOOP_COMPAT__H

#  include <glib.h>
#  include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker mainloop API
 * \ingroup core
 * \deprecated Do not include this header directly. The main loop APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Use crm_signal_handler() instead
gboolean crm_signal(int sig, void (*dispatch) (int sig));

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_MAINLOOP_COMPAT__H
