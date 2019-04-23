/*
 * Copyright 2011-2018 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef CIB_SECRETS__H
#define CIB_SECRETS__H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * load parameters from an ini file (cib_secrets.c)
 */
int replace_secret_params(const char *rsc_id, GHashTable *params);

#ifdef __cplusplus
}
#endif

#endif
