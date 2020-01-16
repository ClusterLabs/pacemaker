/*
 * Copyright 2012-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef CRM_ERROR__H
#  define CRM_ERROR__H
#  include <crm_config.h>
#  include <assert.h>

/*!
 * \file
 * \brief Function and executable result codes
 * \ingroup core
 */

#  define CRM_ASSERT(expr) do {						\
	if(__unlikely((expr) == FALSE)) {				\
	    crm_abort(__FILE__, __FUNCTION__, __LINE__, #expr, TRUE, FALSE); \
            abort(); /* Redundant but it makes analyzers like coverity and clang happy */ \
	}								\
    } while(0)

/*
 * Function return codes
 *
 * For system error codes, see:
 * - /usr/include/asm-generic/errno.h
 * - /usr/include/asm-generic/errno-base.h
 */

#  define pcmk_ok                       0
#  define PCMK_ERROR_OFFSET             190    /* Replacements on non-linux systems, see include/portability.h */
#  define PCMK_CUSTOM_OFFSET            200    /* Purely custom codes */
#  define pcmk_err_generic              201
#  define pcmk_err_no_quorum            202
#  define pcmk_err_schema_validation    203
#  define pcmk_err_transform_failed     204
#  define pcmk_err_old_data             205
#  define pcmk_err_diff_failed          206
#  define pcmk_err_diff_resync          207
#  define pcmk_err_cib_modified         208
#  define pcmk_err_cib_backup           209
#  define pcmk_err_cib_save             210
#  define pcmk_err_schema_unchanged     211
#  define pcmk_err_cib_corrupt          212
#  define pcmk_err_multiple             213
#  define pcmk_err_node_unknown         214
#  define pcmk_err_already              215
#  define pcmk_err_bad_nvpair           216
#  define pcmk_err_unknown_format       217
#  define pcmk_err_panic                255

const char *pcmk_strerror(int rc);
const char *pcmk_errorname(int rc);
const char *bz2_strerror(int rc);

#endif
