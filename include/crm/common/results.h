/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__CRM_COMMON_RESULTS__H
#define PCMK__CRM_COMMON_RESULTS__H

#include <glib.h>           // gboolean

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

/*
 * Function return codes
 *
 * Most Pacemaker API functions return an integer return code. There are two
 * alternative interpretations. The legacy interpration is that the absolute
 * value of the return code is either a system error number or a custom
 * pcmk_err_* number. This is less than ideal because system error numbers are
 * constrained only to the positive int range, so there's the possibility that
 * system errors and custom errors could collide (which did in fact happen
 * already on one architecture). The new intepretation is that negative values
 * are from the pcmk_rc_e enum, and positive values are system error numbers.
 * Both use 0 for success.
 *
 * For system error codes, see:
 * - /usr/include/asm-generic/errno.h
 * - /usr/include/asm-generic/errno-base.h
 */

// Legacy custom return codes for Pacemaker API functions (deprecated)

// NOTE: sbd (as of at least 1.5.2) uses this
#define pcmk_ok                       0

#define PCMK_ERROR_OFFSET             190    /* Replacements on non-linux systems, see include/portability.h */
#define PCMK_CUSTOM_OFFSET            200    /* Purely custom codes */
#define pcmk_err_generic              201
#define pcmk_err_no_quorum            202
#define pcmk_err_schema_validation    203
#define pcmk_err_transform_failed     204
#define pcmk_err_old_data             205

// NOTE: sbd (as of at least 1.5.2) uses this
#define pcmk_err_diff_failed          206

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define pcmk_err_diff_resync          207

#define pcmk_err_cib_modified         208
#define pcmk_err_cib_backup           209
#define pcmk_err_cib_save             210
#define pcmk_err_schema_unchanged     211
#define pcmk_err_cib_corrupt          212
#define pcmk_err_multiple             213
#define pcmk_err_node_unknown         214
#define pcmk_err_already              215
/* On HPPA 215 is ENOSYM (Unknown error 215), which hopefully never happens. */
#ifdef __hppa__
#define pcmk_err_bad_nvpair           250 /* 216 is ENOTSOCK */
#define pcmk_err_unknown_format       252 /* 217 is EDESTADDRREQ */
#else
#define pcmk_err_bad_nvpair           216
#define pcmk_err_unknown_format       217
#endif

/*!
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
    pcmk_rc_digest_mismatch     = -1043,
    pcmk_rc_cs_internal         = -1042,
    pcmk_rc_ipc_more            = -1041,
    pcmk_rc_no_dc               = -1040,
    pcmk_rc_compression         = -1039,
    pcmk_rc_ns_resolution       = -1038,
    pcmk_rc_no_transaction      = -1037,
    pcmk_rc_bad_xml_patch       = -1036,
    pcmk_rc_bad_input           = -1035,
    pcmk_rc_disabled            = -1034,
    pcmk_rc_duplicate_id        = -1033,
    pcmk_rc_unpack_error        = -1032,
    pcmk_rc_invalid_transition  = -1031,
    pcmk_rc_graph_error         = -1030,
    pcmk_rc_dot_error           = -1029,
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

    //! \deprecated Do not use
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

    // NOTE: sbd (as of at least 1.5.2) uses this
    pcmk_rc_ok                  =     0

    // Positive values reserved for system error numbers
};


/*!
 * \brief Exit status codes for resource agents
 *
 * The OCF Resource Agent API standard enumerates the possible exit status codes
 * that agents should return. Besides being used with OCF agents, these values
 * are also used by the executor as a universal status for all agent standards;
 * actual results are mapped to these before returning them to clients.
 */
enum ocf_exitcode {
    PCMK_OCF_OK                   = 0,   //!< Success

    // NOTE: booth (as of at least 1.1) uses this value
    PCMK_OCF_UNKNOWN_ERROR        = 1,   //!< Unspecified error

    PCMK_OCF_INVALID_PARAM        = 2,   //!< Parameter invalid (in local context)
    PCMK_OCF_UNIMPLEMENT_FEATURE  = 3,   //!< Requested action not implemented
    PCMK_OCF_INSUFFICIENT_PRIV    = 4,   //!< Insufficient privileges
    PCMK_OCF_NOT_INSTALLED        = 5,   //!< Dependencies not available locally
    PCMK_OCF_NOT_CONFIGURED       = 6,   //!< Parameter invalid (inherently)

    // NOTE: booth (as of at least 1.1) uses this value
    PCMK_OCF_NOT_RUNNING          = 7,   //!< Service safely stopped

    PCMK_OCF_RUNNING_PROMOTED     = 8,   //!< Service active and promoted
    PCMK_OCF_FAILED_PROMOTED      = 9,   //!< Service failed and possibly in promoted role
    PCMK_OCF_DEGRADED             = 190, //!< Service active but more likely to fail soon
    PCMK_OCF_DEGRADED_PROMOTED    = 191, //!< Service promoted but more likely to fail soon

    /* These two are Pacemaker extensions, not in the OCF standard. The
     * controller records PCMK_OCF_UNKNOWN for pending actions.
     * PCMK_OCF_CONNECTION_DIED is used only with older DCs that don't support
     * PCMK_EXEC_NOT_CONNECTED.
     */
    PCMK_OCF_CONNECTION_DIED      = 189, //!< \deprecated See PCMK_EXEC_NOT_CONNECTED
    PCMK_OCF_UNKNOWN              = 193, //!< Action is pending
};

// NOTE: sbd (as of at least 1.5.2) uses this
/*!
 * \brief Exit status codes for tools and daemons
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
 * application use. OCF adds 8-9 and 190-191.
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
 *
 * \note When new exit codes are added here, remember to also update
 *       python/pacemaker/exitstatus.py.
 *
 * \deprecated Use \c crm_exit_t instead of <tt>enum crm_exit_e</tt>.
 */
typedef enum crm_exit_e {
    // Common convention
    CRM_EX_OK                   =   0, //!< Success
    CRM_EX_ERROR                =   1, //!< Unspecified error

    // LSB + OCF
    CRM_EX_INVALID_PARAM        =   2, //!< Parameter invalid (in local context)
    CRM_EX_UNIMPLEMENT_FEATURE  =   3, //!< Requested action not implemented
    CRM_EX_INSUFFICIENT_PRIV    =   4, //!< Insufficient privileges
    CRM_EX_NOT_INSTALLED        =   5, //!< Dependencies not available locally
    CRM_EX_NOT_CONFIGURED       =   6, //!< Parameter invalid (inherently)
    CRM_EX_NOT_RUNNING          =   7, //!< Service safely stopped
    CRM_EX_PROMOTED             =   8, //!< Service active and promoted
    CRM_EX_FAILED_PROMOTED      =   9, //!< Service failed and possibly promoted

    // sysexits.h
    CRM_EX_USAGE                =  64, //!< Command line usage error
    CRM_EX_DATAERR              =  65, //!< User-supplied data incorrect
    CRM_EX_NOINPUT              =  66, //!< Input file not available
    CRM_EX_NOUSER               =  67, //!< User does not exist
    CRM_EX_NOHOST               =  68, //!< Host unknown
    CRM_EX_UNAVAILABLE          =  69, //!< Needed service unavailable
    CRM_EX_SOFTWARE             =  70, //!< Internal software bug
    CRM_EX_OSERR                =  71, //!< External (OS/environmental) problem
    CRM_EX_OSFILE               =  72, //!< System file not usable
    CRM_EX_CANTCREAT            =  73, //!< File couldn't be created
    CRM_EX_IOERR                =  74, //!< File I/O error
    CRM_EX_TEMPFAIL             =  75, //!< Try again
    CRM_EX_PROTOCOL             =  76, //!< Protocol violated
    CRM_EX_NOPERM               =  77, //!< Non-file permission issue
    CRM_EX_CONFIG               =  78, //!< Misconfiguration

    // Custom
    CRM_EX_FATAL                = 100, //!< Do not respawn
    CRM_EX_PANIC                = 101, //!< Panic the local host
    CRM_EX_DISCONNECT           = 102, //!< Lost connection to something
    CRM_EX_OLD                  = 103, //!< Update older than existing config
    CRM_EX_DIGEST               = 104, //!< Digest comparison failed
    CRM_EX_NOSUCH               = 105, //!< Requested item does not exist
    CRM_EX_QUORUM               = 106, //!< Local partition does not have quorum
    CRM_EX_UNSAFE               = 107, //!< Requires --force or new conditions
    CRM_EX_EXISTS               = 108, //!< Requested item already exists
    CRM_EX_MULTIPLE             = 109, //!< Requested item has multiple matches
    CRM_EX_EXPIRED              = 110, //!< Requested item has expired
    CRM_EX_NOT_YET_IN_EFFECT    = 111, //!< Requested item is not in effect
    CRM_EX_INDETERMINATE        = 112, //!< Could not determine status
    CRM_EX_UNSATISFIED          = 113, //!< Requested item does not satisfy constraints
    CRM_EX_NO_DC                = 114, //!< DC is not yet elected, e.g. right after cluster restart

    // Other
    CRM_EX_TIMEOUT              = 124, //!< Convention from timeout(1)

    /* Anything above 128 overlaps with some shells' use of these values for
     * "interrupted by signal N", and so may be unreliable when detected by
     * shell scripts.
     */

    // OCF Resource Agent API 1.1
    CRM_EX_DEGRADED             = 190, //!< Service active but more likely to fail soon
    CRM_EX_DEGRADED_PROMOTED    = 191, //!< Service promoted but more likely to fail soon

    /* Custom
     *
     * This can be used to initialize exit status variables or to indicate that
     * a command is pending (which is what the controller uses it for).
     */
    CRM_EX_NONE                 = 193, //!< No exit status available

    CRM_EX_MAX                  = 255, //!< Ensure crm_exit_t can hold this
} crm_exit_t;

/*!
 * \brief Execution status
 *
 * These codes are used to specify the result of the attempt to execute an
 * agent, rather than the agent's result itself.
 */
enum pcmk_exec_status {
    PCMK_EXEC_UNKNOWN = -2,     //!< Used only to initialize variables
    PCMK_EXEC_PENDING = -1,     //!< Action is in progress
    PCMK_EXEC_DONE,             //!< Action completed, result is known
    PCMK_EXEC_CANCELLED,        //!< Action was cancelled
    PCMK_EXEC_TIMEOUT,          //!< Action did not complete in time
    PCMK_EXEC_NOT_SUPPORTED,    //!< Agent does not implement requested action
    PCMK_EXEC_ERROR,            //!< Execution failed, may be retried
    PCMK_EXEC_ERROR_HARD,       //!< Execution failed, do not retry on node
    PCMK_EXEC_ERROR_FATAL,      //!< Execution failed, do not retry anywhere
    PCMK_EXEC_NOT_INSTALLED,    //!< Agent or dependency not available locally
    PCMK_EXEC_NOT_CONNECTED,    //!< No connection to executor
    PCMK_EXEC_INVALID,          //!< Action cannot be attempted (e.g. shutdown)
    PCMK_EXEC_NO_FENCE_DEVICE,  //!< No fence device is configured for target
    PCMK_EXEC_NO_SECRETS,       //!< Necessary CIB secrets are unavailable

    // Add new values above here then update this one below
    PCMK_EXEC_MAX = PCMK_EXEC_NO_SECRETS, //!< Maximum value for this enum
};

/*!
 * \brief Types of Pacemaker result codes
 *
 * A particular integer can have different meanings within different Pacemaker
 * result code families. It may be interpretable within zero, one, or multiple
 * families.
 *
 * These values are useful for specifying how an integer result code should be
 * interpreted in situations involving a generic integer value. For example, a
 * function that can process multiple types of result codes might accept an
 * arbitrary integer argument along with a \p pcmk_result_type argument that
 * specifies how to interpret the integer.
 */
enum pcmk_result_type {
    pcmk_result_legacy      = 0,  //!< Legacy API function return code
    pcmk_result_rc          = 1,  //!< Standard Pacemaker return code
    pcmk_result_exitcode    = 2,  //!< Exit status code
    pcmk_result_exec_status = 3,  //!< Execution status
};

int pcmk_result_get_strings(int code, enum pcmk_result_type type,
                            const char **name, const char **desc);
const char *pcmk_rc_name(int rc);

// NOTE: sbd (as of at least 1.5.2) uses this
const char *pcmk_rc_str(int rc);

crm_exit_t pcmk_rc2exitc(int rc);
enum ocf_exitcode pcmk_rc2ocf(int rc);
int pcmk_rc2legacy(int rc);
int pcmk_legacy2rc(int legacy_rc);

// NOTE: sbd (as of at least 1.5.2) uses this
const char *pcmk_strerror(int rc);

const char *pcmk_errorname(int rc);
const char *crm_exit_name(crm_exit_t exit_code);

// NOTE: sbd (as of at least 1.5.2) uses this
const char *crm_exit_str(crm_exit_t exit_code);

_Noreturn crm_exit_t crm_exit(crm_exit_t rc);

/* coverity[+kill] */
void crm_abort(const char *file, const char *function, int line,
               const char *condition, gboolean do_core, gboolean do_fork);

static inline const char *
pcmk_exec_status_str(enum pcmk_exec_status status)
{
    switch (status) {
        case PCMK_EXEC_PENDING:         return "Pending";
        case PCMK_EXEC_DONE:            return "Done";
        case PCMK_EXEC_CANCELLED:       return "Cancelled";
        case PCMK_EXEC_TIMEOUT:         return "Timed out";
        case PCMK_EXEC_NOT_SUPPORTED:   return "Unsupported";
        case PCMK_EXEC_ERROR:           return "Error";
        case PCMK_EXEC_ERROR_HARD:      return "Hard error";
        case PCMK_EXEC_ERROR_FATAL:     return "Fatal error";
        case PCMK_EXEC_NOT_INSTALLED:   return "Not installed";
        case PCMK_EXEC_NOT_CONNECTED:   return "Internal communication failure";
        case PCMK_EXEC_INVALID:         return "Cannot execute now";
        case PCMK_EXEC_NO_FENCE_DEVICE: return "No fence device";
        case PCMK_EXEC_NO_SECRETS:      return "CIB secrets unavailable";
        default:                        return "Unrecognized status (bug?)";
    }
}

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/results_compat.h>
#endif

#endif
