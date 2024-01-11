/*
 * Copyright 2023-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_CIB_INTERNAL__H
#define PCMK__CRM_COMMON_CIB_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

const char *pcmk__cib_abs_xpath_for(const char *element);

int pcmk__check_feature_set(const char *cib_version);

#ifdef __cplusplus
}
#endif

#endif // PCMK__COMMON_CIB_INTERNAL__H
