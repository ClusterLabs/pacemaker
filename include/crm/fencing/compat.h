/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__FENCING_COMPAT__H
#  define PCMK__FENCING_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker fencing API
 * \ingroup fencing
 * \deprecated Do not include this header directly. The fencing APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Use stonith_get_namespace() instead
const char *get_stonith_provider(const char *agent, const char *provider);

#ifdef __cplusplus
}
#endif

#endif // PCMK__FENCING_COMPAT__H
