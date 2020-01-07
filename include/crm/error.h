/*
 * Copyright 2012-2020 the Pacemaker project contributors
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
 * Most Pacemaker API functions return an integer return code. There are two
 * alternative interpretations. The legacy interpration is that the absolute
 * value of the return code is either a system error number or a custom
 * pcmk_err_* number. This is less than ideal because system error numbers are
 * constrained only to the positive int range, so there's the possibility
 * (though not noticed in the wild) that system errors and custom errors could
 * collide. The new intepretation is that negative values are from the pcmk_rc_e
 * enum, and positive values are system error numbers. Both use 0 for success.
 *
 * For system error codes, see:
 * - /usr/include/asm-generic/errno.h
 * - /usr/include/asm-generic/errno-base.h
 */

// Legacy custom return codes for Pacemaker API functions
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
/* On HPPA 215 is ENOSYM (Unknown error 215), which hopefully never happens. */
#ifdef __hppa__
#  define pcmk_err_bad_nvpair           250	/* 216 is ENOTSOCK */
#  define pcmk_err_unknown_format       252	/* 217 is EDESTADDRREQ */
#else
#  define pcmk_err_bad_nvpair           216
#  define pcmk_err_unknown_format       217
#endif
#  define pcmk_err_panic                255

/*!
 * \enum pcmk_rc_e
 * \brief Return codes for Pacemaker API functions
 *
 * Any Pacemaker API function documented as returning a "standard Pacemaker
 * return code" will return pcmk_rc_ok (0) on success, and one of this
 * enumeration's other (negative) values or a (positive) system error number
 * otherwise. The custom codes are at -1001 and lower, so that the caller may
 * use -1 through -1000 for their own custom values if desired. While generally
 * referred to as "errors", nonzero values simply indicate a result, which might
 * or might not be an error depending on the calling context.
 */
enum pcmk_rc_e {
    /* When adding new values, use consecutively lower numbers, update the array
     * in lib/common/logging.c and test with crm_error.
     */
    pcmk_rc_no_quorum           = -1017,
    pcmk_rc_schema_validation   = -1016,
    pcmk_rc_schema_unchanged    = -1015,
    pcmk_rc_transform_failed    = -1014,
    pcmk_rc_old_data            = -1013,
    pcmk_rc_diff_failed         = -1012,
    pcmk_rc_diff_resync         = -1011,
    pcmk_rc_cib_modified        = -1010,
    pcmk_rc_cib_backup          = -1009,
    pcmk_rc_cib_save            = -1008,
    pcmk_rc_cib_corrupt         = -1007,
    pcmk_rc_multiple            = -1006,
    pcmk_rc_node_unknown        = -1005,
    pcmk_rc_already             = -1004,
    pcmk_rc_bad_nvpair          = -1003,
    pcmk_rc_unknown_format      = -1002,
    // Developers: Use a more specific code than pcmk_rc_error whenever possible
    pcmk_rc_error               = -1001,

    // Values -1 through -1000 reserved for caller use

    pcmk_rc_ok                  =     0

    // Positive values reserved for system error numbers
};

const char *pcmk_rc_name(int rc);
const char *pcmk_rc_str(int rc);
int pcmk_rc2legacy(int rc);
int pcmk_legacy2rc(int legacy_rc);
const char *pcmk_strerror(int rc);
const char *pcmk_errorname(int rc);
const char *bz2_strerror(int rc);

#endif
