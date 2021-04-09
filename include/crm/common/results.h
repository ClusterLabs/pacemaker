/*
 * Copyright 2012-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef CRM_RESULTS__H
#  define CRM_RESULTS__H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Function and executable result codes
 * \ingroup core
 */

// Lifted from config.h
/* The _Noreturn keyword of C11.  */
#ifndef _Noreturn
# if (defined __cplusplus \
      && ((201103 <= __cplusplus && !(__GNUC__ == 4 && __GNUC_MINOR__ == 7)) \
          || (defined _MSC_VER && 1900 <= _MSC_VER)))
#  define _Noreturn [[noreturn]]
# elif ((!defined __cplusplus || defined __clang__) \
        && (201112 <= (defined __STDC_VERSION__ ? __STDC_VERSION__ : 0)  \
            || 4 < __GNUC__ + (7 <= __GNUC_MINOR__)))
   /* _Noreturn works as-is.  */
# elif 2 < __GNUC__ + (8 <= __GNUC_MINOR__) || 0x5110 <= __SUNPRO_C
#  define _Noreturn __attribute__ ((__noreturn__))
# elif 1200 <= (defined _MSC_VER ? _MSC_VER : 0)
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn
# endif
#endif

#  define CRM_ASSERT(expr) do {                                              \
        if (!(expr)) {                                                       \
            crm_abort(__FILE__, __func__, __LINE__, #expr, TRUE, FALSE);     \
            abort(); /* crm_abort() doesn't always abort! */                 \
        }                                                                    \
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

// Legacy custom return codes for Pacemaker API functions (deprecated)
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
     * in lib/common/results.c, and test with crm_error.
     */
    pcmk_rc_underflow           = -1028,
    pcmk_rc_no_input            = -1027,
    pcmk_rc_no_output           = -1026,
    pcmk_rc_after_range         = -1025,
    pcmk_rc_within_range        = -1024,
    pcmk_rc_before_range        = -1023,
    pcmk_rc_undetermined        = -1022,
    pcmk_rc_op_unsatisfied      = -1021,
    pcmk_rc_ipc_pid_only        = -1020,
    pcmk_rc_ipc_unresponsive    = -1019,
    pcmk_rc_ipc_unauthorized    = -1018,
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

/* Uniform exit codes
 * Everything is mapped to its OCF equivalent so that Pacemaker only deals with one set of codes
 */
enum ocf_exitcode {
    PCMK_OCF_OK                   = 0,
    PCMK_OCF_UNKNOWN_ERROR        = 1,
    PCMK_OCF_INVALID_PARAM        = 2,
    PCMK_OCF_UNIMPLEMENT_FEATURE  = 3,
    PCMK_OCF_INSUFFICIENT_PRIV    = 4,
    PCMK_OCF_NOT_INSTALLED        = 5,
    PCMK_OCF_NOT_CONFIGURED       = 6,
    PCMK_OCF_NOT_RUNNING          = 7,  /* End of overlap with LSB */
    PCMK_OCF_RUNNING_PROMOTED     = 8,
    PCMK_OCF_FAILED_PROMOTED      = 9,


    /* 150-199	reserved for application use */
    PCMK_OCF_CONNECTION_DIED = 189, // Deprecated (see PCMK_LRM_OP_NOT_CONNECTED)

    PCMK_OCF_DEGRADED           = 190, // Resource active but more likely to fail soon
    PCMK_OCF_DEGRADED_PROMOTED  = 191, // Resource promoted but more likely to fail soon

    PCMK_OCF_EXEC_ERROR    = 192, /* Generic problem invoking the agent */
    PCMK_OCF_UNKNOWN       = 193, /* State of the service is unknown - used for recording in-flight operations */
    PCMK_OCF_SIGNAL        = 194,
    PCMK_OCF_NOT_SUPPORTED = 195,
    PCMK_OCF_PENDING       = 196,
    PCMK_OCF_CANCELLED     = 197,
    PCMK_OCF_TIMEOUT       = 198,
    PCMK_OCF_OTHER_ERROR   = 199, /* Keep the same codes as PCMK_LSB */

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use PCMK_OCF_RUNNING_PROMOTED instead
    PCMK_OCF_RUNNING_MASTER     = PCMK_OCF_RUNNING_PROMOTED,

    //! \deprecated Use PCMK_OCF_FAILED_PROMOTED instead
    PCMK_OCF_FAILED_MASTER      = PCMK_OCF_FAILED_PROMOTED,

    //! \deprecated Use PCMK_OCF_DEGRADED_PROMOTED instead
    PCMK_OCF_DEGRADED_MASTER    = PCMK_OCF_DEGRADED_PROMOTED,
#endif
};

/*
 * Exit status codes
 *
 * We want well-specified (i.e. OS-invariant) exit status codes for our daemons
 * and applications so they can be relied on by callers. (Function return codes
 * and errno's do not make good exit statuses.)
 *
 * The only hard rule is that exit statuses must be between 0 and 255; all else
 * is convention. Universally, 0 is success, and 1 is generic error (excluding
 * OSes we don't support -- for example, OpenVMS considers 1 success!).
 *
 * For init scripts, the LSB gives meaning to 0-7, and sets aside 150-199 for
 * application use. OCF adds 8-9 and 189-199.
 *
 * sysexits.h was an attempt to give additional meanings, but never really
 * caught on. It uses 0 and 64-78.
 *
 * Bash reserves 2 ("incorrect builtin usage") and 126-255 (126 is "command
 * found but not executable", 127 is "command not found", 128 + n is
 * "interrupted by signal n").
 *
 * tldp.org recommends 64-113 for application use.
 *
 * We try to overlap with the above conventions when practical.
 */
typedef enum crm_exit_e {
    // Common convention
    CRM_EX_OK                   =   0,
    CRM_EX_ERROR                =   1,

    // LSB + OCF
    CRM_EX_INVALID_PARAM        =   2,
    CRM_EX_UNIMPLEMENT_FEATURE  =   3,
    CRM_EX_INSUFFICIENT_PRIV    =   4,
    CRM_EX_NOT_INSTALLED        =   5,
    CRM_EX_NOT_CONFIGURED       =   6,
    CRM_EX_NOT_RUNNING          =   7,

    // sysexits.h
    CRM_EX_USAGE                =  64, // command line usage error
    CRM_EX_DATAERR              =  65, // user-supplied data incorrect
    CRM_EX_NOINPUT              =  66, // input file not available
    CRM_EX_NOUSER               =  67, // user does not exist
    CRM_EX_NOHOST               =  68, // host unknown
    CRM_EX_UNAVAILABLE          =  69, // needed service unavailable
    CRM_EX_SOFTWARE             =  70, // internal software bug
    CRM_EX_OSERR                =  71, // external (OS/environmental) problem
    CRM_EX_OSFILE               =  72, // system file not usable
    CRM_EX_CANTCREAT            =  73, // file couldn't be created
    CRM_EX_IOERR                =  74, // file I/O error
    CRM_EX_TEMPFAIL             =  75, // try again
    CRM_EX_PROTOCOL             =  76, // protocol violated
    CRM_EX_NOPERM               =  77, // non-file permission issue
    CRM_EX_CONFIG               =  78, // misconfiguration

    // Custom
    CRM_EX_FATAL                = 100, // do not respawn
    CRM_EX_PANIC                = 101, // panic the local host
    CRM_EX_DISCONNECT           = 102, // lost connection to something
    CRM_EX_OLD                  = 103, // update older than existing config
    CRM_EX_DIGEST               = 104, // digest comparison failed
    CRM_EX_NOSUCH               = 105, // requested item does not exist
    CRM_EX_QUORUM               = 106, // local partition does not have quorum
    CRM_EX_UNSAFE               = 107, // requires --force or new conditions
    CRM_EX_EXISTS               = 108, // requested item already exists
    CRM_EX_MULTIPLE             = 109, // requested item has multiple matches
    CRM_EX_EXPIRED              = 110, // requested item has expired
    CRM_EX_NOT_YET_IN_EFFECT    = 111, // requested item is not in effect
    CRM_EX_INDETERMINATE        = 112, // could not determine status
    CRM_EX_UNSATISFIED          = 113, // requested item does not satisfy constraints

    // Other
    CRM_EX_TIMEOUT              = 124, // convention from timeout(1)
    CRM_EX_MAX                  = 255, // ensure crm_exit_t can hold this
} crm_exit_t;

const char *pcmk_rc_name(int rc);
const char *pcmk_rc_str(int rc);
crm_exit_t pcmk_rc2exitc(int rc);
int pcmk_rc2legacy(int rc);
int pcmk_legacy2rc(int legacy_rc);
const char *pcmk_strerror(int rc);
const char *pcmk_errorname(int rc);
const char *bz2_strerror(int rc);
crm_exit_t crm_errno2exit(int rc);
const char *crm_exit_name(crm_exit_t exit_code);
const char *crm_exit_str(crm_exit_t exit_code);
_Noreturn crm_exit_t crm_exit(crm_exit_t rc);

#ifdef __cplusplus
}
#endif

#endif
