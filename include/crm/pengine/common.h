/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_COMMON__H
#  define PCMK__CRM_PENGINE_COMMON__H

#  include <glib.h>
#  include <regex.h>
#  include <crm/common/iso8601.h>
#  include <crm/common/scheduler.h>

/**
 * \file
 * \brief Deprecated Pacemaker shared API for scheduler and rules
 * \ingroup pengine
 * \deprecated Do not include this header directly. The APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/pengine/common_compat.h>
#else
#error Do not include the deprecated header crm/pengine/common.h
#endif

#endif
