/*
 * Copyright (C) 2012-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef CRM_RESULTS__H
#  define CRM_RESULTS__H

/*!
 * \file
 * \brief Function and executable result codes
 * \ingroup core
 */

#  define CRM_ASSERT(expr) do {                                              \
        if(__unlikely((expr) == FALSE)) {                                    \
            crm_abort(__FILE__, __FUNCTION__, __LINE__, #expr, TRUE, FALSE); \
            abort(); /* Redundant but it makes static analyzers happy */     \
        }                                                                    \
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

    // Other
    CRM_EX_TIMEOUT              = 124, // convention from timeout(1)
    CRM_EX_MAX                  = 255, // ensure crm_exit_t can hold this
} crm_exit_t;

const char *pcmk_strerror(int rc);
const char *pcmk_errorname(int rc);
const char *bz2_strerror(int rc);
crm_exit_t crm_errno2exit(int rc);
const char *crm_exit_name(crm_exit_t exit_code);
const char *crm_exit_str(crm_exit_t exit_code);
crm_exit_t crm_exit(crm_exit_t rc);

#endif
