/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_LOGGING_COMPAT__H
#define PCMK__CRM_COMMON_LOGGING_COMPAT__H

#include <stdint.h>         // uint8_t
#include <glib.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker logging API
 * \ingroup core
 * \deprecated Do not include this header directly. Do not use Pacemaker
 *             libraries for general-purpose logging; libqb's logging API is a
 *             suitable replacement. The logging APIs in this header, and the
 *             header itself, will be removed in a future release.
 */

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_LOGGING_COMPAT__H
