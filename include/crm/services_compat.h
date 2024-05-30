/*
 * Copyright 2010-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_SERVICES_COMPAT__H
#  define PCMK__CRM_SERVICES_COMPAT__H

#include <crm/common/actions.h>
#include <crm/common/results.h>
#include <crm/services.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Deprecated services API
 * \ingroup core
 * \deprecated Do not include this header directly. The service APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

#  ifndef LSB_ROOT_DIR
     //! \deprecated Do not use
#    define LSB_ROOT_DIR "/etc/init.d"
#  endif

#ifdef __cplusplus
}
#endif

#endif
