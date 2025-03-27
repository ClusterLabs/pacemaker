/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <bzlib.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <qb/qbdefs.h>

#include <crm/common/mainloop.h>
#include <crm/common/xml.h>

G_DEFINE_QUARK(pcmk-rc-error-quark, pcmk__rc_error)
G_DEFINE_QUARK(pcmk-exitc-error-quark, pcmk__exitc_error)

// General (all result code types)

/*!
 * \brief Get the name and description of a given result code
 *
 * A result code can be interpreted as a member of any one of several families.
 *
 * \param[in]  code  The result code to look up
 * \param[in]  type  How \p code should be interpreted
 * \param[out] name  Where to store the result code's name
 * \param[out] desc  Where to store the result code's description
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_result_get_strings(int code, enum pcmk_result_type type, const char **name,
                        const char **desc)
{
    const char *code_name = NULL;
    const char *code_desc = NULL;

    switch (type) {
        case pcmk_result_legacy:
            code_name = pcmk_errorname(code);
            code_desc = pcmk_strerror(code);
            break;
        case pcmk_result_rc:
            code_name = pcmk_rc_name(code);
            code_desc = pcmk_rc_str(code);
            break;
        case pcmk_result_exitcode:
            code_name = crm_exit_name(code);
            code_desc = crm_exit_str((crm_exit_t) code);
            break;
        default:
            return pcmk_rc_undetermined;
    }

    if (name != NULL) {
        *name = code_name;
    }
    
    if (desc != NULL) {
        *desc = code_desc;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Get the lower and upper bounds of a result code family
 *
 * \param[in]   type    Type of result code
 * \param[out]  lower   Where to store the lower bound
 * \param[out]  upper   Where to store the upper bound
 *
 * \return Standard Pacemaker return code
 *
 * \note There is no true upper bound on standard Pacemaker return codes or
 *       legacy return codes. All system \p errno values are valid members of
 *       these result code families, and there is no global upper limit nor a
 *       constant by which to refer to the highest \p errno value on a given
 *       system.
 */
int
pcmk__result_bounds(enum pcmk_result_type type, int *lower, int *upper)
{
    pcmk__assert((lower != NULL) && (upper != NULL));

    switch (type) {
        case pcmk_result_legacy:
            *lower = pcmk_ok;
            *upper = 256;   // should be enough for almost any system error code
            break;
        case pcmk_result_rc:
            *lower = pcmk_rc_error - pcmk__n_rc + 1;
            *upper = 256;
            break;
        case pcmk_result_exitcode:
            *lower = CRM_EX_OK;
            *upper = CRM_EX_MAX;
            break;
        default:
            *lower = 0;
            *upper = -1;
            return pcmk_rc_undetermined;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Log a failed assertion
 *
 * \param[in] file              File making the assertion
 * \param[in] function          Function making the assertion
 * \param[in] line              Line of file making the assertion
 * \param[in] assert_condition  String representation of assertion
 */
static void
log_assertion_as(const char *file, const char *function, int line,
                 const char *assert_condition)
{
    if (!pcmk__is_daemon) {
        crm_enable_stderr(TRUE); // Make sure command-line user sees message
    }
    pcmk__err("%s: Triggered fatal assertion at %s:%d : %s", function, file,
              line, assert_condition);
}

/* coverity[+kill] */
/*!
 * \internal
 * \brief Log a failed assertion and abort
 *
 * \param[in] file              File making the assertion
 * \param[in] function          Function making the assertion
 * \param[in] line              Line of file making the assertion
 * \param[in] assert_condition  String representation of assertion
 *
 * \note This does not return
 */
_Noreturn void
pcmk__abort_as(const char *file, const char *function, int line,
               const char *assert_condition)
{
    log_assertion_as(file, function, line, assert_condition);
    abort();
}

/* coverity[+kill] */
/*!
 * \internal
 * \brief Handle a failed assertion
 *
 * When called by a daemon, fork a child that aborts (to dump core), otherwise
 * abort the current process.
 *
 * \param[in] file              File making the assertion
 * \param[in] function          Function making the assertion
 * \param[in] line              Line of file making the assertion
 * \param[in] assert_condition  String representation of assertion
 */
static void
fail_assert_as(const char *file, const char *function, int line,
               const char *assert_condition)
{
    int status = 0;
    pid_t pid = 0;

    if (!pcmk__is_daemon) {
        pcmk__abort_as(file, function, line, assert_condition); // No return
    }

    pid = fork();
    switch (pid) {
        case -1: // Fork failed
            pcmk__warn("%s: Cannot dump core for non-fatal assertion at %s:%d "
                       ": %s", function, file, line, assert_condition);
            break;

        case 0: // Child process: just abort to dump core
            abort();
            break;

        default: // Parent process: wait for child
            pcmk__err("%s: Forked child [%d] to record non-fatal assertion at "
                      "%s:%d : %s",
                      function, pid, file, line, assert_condition);
            crm_write_blackbox(SIGTRAP, NULL);
            do {
                if (waitpid(pid, &status, 0) == pid) {
                    return; // Child finished dumping core
                }
            } while (errno == EINTR);
            if (errno == ECHILD) {
                // crm_mon ignores SIGCHLD
                crm_trace("Cannot wait on forked child [%d] "
                          "(SIGCHLD is probably ignored)", pid);
            } else {
                pcmk__err("Cannot wait on forked child [%d]: %s", pid,
                          pcmk_rc_str(errno));
            }
            break;
    }
}

/* coverity[+kill] */
void
crm_abort(const char *file, const char *function, int line,
          const char *assert_condition, gboolean do_core, gboolean do_fork)
{
    if (!do_fork) {
        pcmk__abort_as(file, function, line, assert_condition); // No return
    } else if (do_core) {
        fail_assert_as(file, function, line, assert_condition);
    } else {
        log_assertion_as(file, function, line, assert_condition);
    }
}

// @COMPAT Legacy function return codes

//! \deprecated Use standard return codes and pcmk_rc_name() instead
const char *
pcmk_errorname(int rc)
{
    rc = abs(rc);
    switch (rc) {
        case pcmk_err_generic: return "pcmk_err_generic";
        case pcmk_err_no_quorum: return "pcmk_err_no_quorum";
        case pcmk_err_schema_validation: return "pcmk_err_schema_validation";
        case pcmk_err_transform_failed: return "pcmk_err_transform_failed";
        case pcmk_err_old_data: return "pcmk_err_old_data";
        case pcmk_err_diff_failed: return "pcmk_err_diff_failed";
        case pcmk_err_diff_resync: return "pcmk_err_diff_resync";
        case pcmk_err_cib_modified: return "pcmk_err_cib_modified";
        case pcmk_err_cib_backup: return "pcmk_err_cib_backup";
        case pcmk_err_cib_save: return "pcmk_err_cib_save";
        case pcmk_err_cib_corrupt: return "pcmk_err_cib_corrupt";
        case pcmk_err_multiple: return "pcmk_err_multiple";
        case pcmk_err_node_unknown: return "pcmk_err_node_unknown";
        case pcmk_err_already: return "pcmk_err_already";
        case pcmk_err_bad_nvpair: return "pcmk_err_bad_nvpair";
        case pcmk_err_unknown_format: return "pcmk_err_unknown_format";
        default: return pcmk_rc_name(rc); // system errno
    }
}

//! \deprecated Use standard return codes and pcmk_rc_str() instead
const char *
pcmk_strerror(int rc)
{
    return pcmk_rc_str(pcmk_legacy2rc(rc));
}

// Standard Pacemaker API return codes

/* This array is used only for nonzero values of pcmk_rc_e. Its values must be
 * kept in the exact reverse order of the enum value numbering (i.e. add new
 * values to the end of the array).
 */
static const struct pcmk__rc_info {
    const char *name;
    const char *desc;
    int legacy_rc;
} pcmk__rcs[] = {
    { "pcmk_rc_error",
      "Error",
      -pcmk_err_generic,
    },
    { "pcmk_rc_unknown_format",
      "Unknown output format",
      -pcmk_err_unknown_format,
    },
    { "pcmk_rc_bad_nvpair",
      "Bad name/value pair given",
      -pcmk_err_bad_nvpair,
    },
    { "pcmk_rc_already",
      "Already in requested state",
      -pcmk_err_already,
    },
    { "pcmk_rc_node_unknown",
      "Node not found",
      -pcmk_err_node_unknown,
    },
    { "pcmk_rc_multiple",
      "Resource active on multiple nodes",
      -pcmk_err_multiple,
    },
    { "pcmk_rc_cib_corrupt",
      "Could not parse on-disk configuration",
      -pcmk_err_cib_corrupt,
    },
    { "pcmk_rc_cib_save",
      "Could not save new configuration to disk",
      -pcmk_err_cib_save,
    },
    { "pcmk_rc_cib_backup",
      "Could not archive previous configuration",
      -pcmk_err_cib_backup,
    },
    { "pcmk_rc_cib_modified",
      "On-disk configuration was manually modified",
      -pcmk_err_cib_modified,
    },
    { "pcmk_rc_diff_resync",
      "Application of update diff failed, requesting full refresh",
      -pcmk_err_diff_resync,
    },
    { "pcmk_rc_diff_failed",
      "Application of update diff failed",
      -pcmk_err_diff_failed,
    },
    { "pcmk_rc_old_data",
      "Update was older than existing configuration",
      -pcmk_err_old_data,
    },
    { "pcmk_rc_transform_failed",
      "Schema transform failed",
      -pcmk_err_transform_failed,
    },
    { "pcmk_rc_schema_unchanged",
      "Schema is already the latest available",
      -pcmk_err_schema_unchanged,
    },
    { "pcmk_rc_schema_validation",
      "Update does not conform to the configured schema",
      -pcmk_err_schema_validation,
    },
    { "pcmk_rc_no_quorum",
      "Operation requires quorum",
      -pcmk_err_no_quorum,
    },
    { "pcmk_rc_ipc_unauthorized",
      "IPC server is blocked by unauthorized process",
      -pcmk_err_generic,
    },
    { "pcmk_rc_ipc_unresponsive",
      "IPC server is unresponsive",
      -pcmk_err_generic,
    },
    { "pcmk_rc_ipc_pid_only",
      "IPC server process is active but not accepting connections",
      -pcmk_err_generic,
    },
    { "pcmk_rc_op_unsatisfied",
      "Not applicable under current conditions",
      -pcmk_err_generic,
    },
    { "pcmk_rc_undetermined",
      "Result undetermined",
      -pcmk_err_generic,
    },
    { "pcmk_rc_before_range",
      "Result occurs before given range",
      -pcmk_err_generic,
    },
    { "pcmk_rc_within_range",
      "Result occurs within given range",
      -pcmk_err_generic,
    },
    { "pcmk_rc_after_range",
      "Result occurs after given range",
      -pcmk_err_generic,
    },
    { "pcmk_rc_no_output",
      "Output message produced no output",
      -pcmk_err_generic,
    },
    { "pcmk_rc_no_input",
      "Input file not available",
      -pcmk_err_generic,
    },
    { "pcmk_rc_underflow",
      "Value too small to be stored in data type",
      -pcmk_err_generic,
    },
    { "pcmk_rc_dot_error",
      "Error writing dot(1) file",
      -pcmk_err_generic,
    },
    { "pcmk_rc_graph_error",
      "Error writing graph file",
      -pcmk_err_generic,
    },
    { "pcmk_rc_invalid_transition",
      "Cluster simulation produced invalid transition",
      -pcmk_err_generic,
    },
    { "pcmk_rc_unpack_error",
      "Unable to parse CIB XML",
      -pcmk_err_generic,
    },
    { "pcmk_rc_duplicate_id",
      "Two or more XML elements have the same ID",
      -pcmk_err_generic,
    },
    { "pcmk_rc_disabled",
      "Disabled",
      -pcmk_err_generic,
    },
    { "pcmk_rc_bad_input",
      "Bad input value provided",
      -pcmk_err_generic,
    },
    { "pcmk_rc_bad_xml_patch",
      "Bad XML patch format",
      -pcmk_err_generic,
    },
    { "pcmk_rc_no_transaction",
      "No active transaction found",
      -pcmk_err_generic,
    },
    { "pcmk_rc_ns_resolution",
      "Nameserver resolution error",
      -pcmk_err_generic,
    },
    { "pcmk_rc_compression",
      "Compression/decompression error",
      -pcmk_err_generic,
    },
    { "pcmk_rc_no_dc",
      "DC is not yet elected",
      -pcmk_err_generic,
    },
};

/*!
 * \internal
 * \brief The number of <tt>enum pcmk_rc_e</tt> values, excluding \c pcmk_rc_ok
 *
 * This constant stores the number of negative standard Pacemaker return codes.
 * These represent Pacemaker-custom error codes. The count does not include
 * positive system error numbers, nor does it include \c pcmk_rc_ok (success).
 */
const size_t pcmk__n_rc = PCMK__NELEM(pcmk__rcs);

/*!
 * \brief Get a return code constant name as a string
 *
 * \param[in] rc  Integer return code to convert
 *
 * \return String of constant name corresponding to rc
 */
const char *
pcmk_rc_name(int rc)
{
    if ((rc <= pcmk_rc_error) && ((pcmk_rc_error - rc) < pcmk__n_rc)) {
        return pcmk__rcs[pcmk_rc_error - rc].name;
    }
    switch (rc) {
        case pcmk_rc_ok:        return "pcmk_rc_ok";
        case E2BIG:             return "E2BIG";
        case EACCES:            return "EACCES";
        case EADDRINUSE:        return "EADDRINUSE";
        case EADDRNOTAVAIL:     return "EADDRNOTAVAIL";
        case EAFNOSUPPORT:      return "EAFNOSUPPORT";
        case EAGAIN:            return "EAGAIN";
        case EALREADY:          return "EALREADY";
        case EBADF:             return "EBADF";
        case EBADMSG:           return "EBADMSG";
        case EBUSY:             return "EBUSY";
        case ECANCELED:         return "ECANCELED";
        case ECHILD:            return "ECHILD";
        case ECOMM:             return "ECOMM";
        case ECONNABORTED:      return "ECONNABORTED";
        case ECONNREFUSED:      return "ECONNREFUSED";
        case ECONNRESET:        return "ECONNRESET";
        /* case EDEADLK:        return "EDEADLK"; */
        case EDESTADDRREQ:      return "EDESTADDRREQ";
        case EDOM:              return "EDOM";
        case EDQUOT:            return "EDQUOT";
        case EEXIST:            return "EEXIST";
        case EFAULT:            return "EFAULT";
        case EFBIG:             return "EFBIG";
        case EHOSTDOWN:         return "EHOSTDOWN";
        case EHOSTUNREACH:      return "EHOSTUNREACH";
        case EIDRM:             return "EIDRM";
        case EILSEQ:            return "EILSEQ";
        case EINPROGRESS:       return "EINPROGRESS";
        case EINTR:             return "EINTR";
        case EINVAL:            return "EINVAL";
        case EIO:               return "EIO";
        case EISCONN:           return "EISCONN";
        case EISDIR:            return "EISDIR";
        case ELIBACC:           return "ELIBACC";
        case ELOOP:             return "ELOOP";
        case EMFILE:            return "EMFILE";
        case EMLINK:            return "EMLINK";
        case EMSGSIZE:          return "EMSGSIZE";
#ifdef EMULTIHOP // Not available on OpenBSD
        case EMULTIHOP:         return "EMULTIHOP";
#endif
        case ENAMETOOLONG:      return "ENAMETOOLONG";
        case ENETDOWN:          return "ENETDOWN";
        case ENETRESET:         return "ENETRESET";
        case ENETUNREACH:       return "ENETUNREACH";
        case ENFILE:            return "ENFILE";
        case ENOBUFS:           return "ENOBUFS";
        case ENODATA:           return "ENODATA";
        case ENODEV:            return "ENODEV";
        case ENOENT:            return "ENOENT";
        case ENOEXEC:           return "ENOEXEC";
        case ENOKEY:            return "ENOKEY";
        case ENOLCK:            return "ENOLCK";
#ifdef ENOLINK // Not available on OpenBSD
        case ENOLINK:           return "ENOLINK";
#endif
        case ENOMEM:            return "ENOMEM";
        case ENOMSG:            return "ENOMSG";
        case ENOPROTOOPT:       return "ENOPROTOOPT";
        case ENOSPC:            return "ENOSPC";
#ifdef ENOSR
        case ENOSR:             return "ENOSR";
#endif
#ifdef ENOSTR
        case ENOSTR:            return "ENOSTR";
#endif
        case ENOSYS:            return "ENOSYS";
        case ENOTBLK:           return "ENOTBLK";
        case ENOTCONN:          return "ENOTCONN";
        case ENOTDIR:           return "ENOTDIR";
        case ENOTEMPTY:         return "ENOTEMPTY";
        case ENOTSOCK:          return "ENOTSOCK";
#if ENOTSUP != EOPNOTSUPP
        case ENOTSUP:           return "ENOTSUP";
#endif
        case ENOTTY:            return "ENOTTY";
        case ENOTUNIQ:          return "ENOTUNIQ";
        case ENXIO:             return "ENXIO";
        case EOPNOTSUPP:        return "EOPNOTSUPP";
        case EOVERFLOW:         return "EOVERFLOW";
        case EPERM:             return "EPERM";
        case EPFNOSUPPORT:      return "EPFNOSUPPORT";
        case EPIPE:             return "EPIPE";
        case EPROTO:            return "EPROTO";
        case EPROTONOSUPPORT:   return "EPROTONOSUPPORT";
        case EPROTOTYPE:        return "EPROTOTYPE";
        case ERANGE:            return "ERANGE";
        case EREMOTE:           return "EREMOTE";
        case EREMOTEIO:         return "EREMOTEIO";
        case EROFS:             return "EROFS";
        case ESHUTDOWN:         return "ESHUTDOWN";
        case ESPIPE:            return "ESPIPE";
        case ESOCKTNOSUPPORT:   return "ESOCKTNOSUPPORT";
        case ESRCH:             return "ESRCH";
        case ESTALE:            return "ESTALE";
        case ETIME:             return "ETIME";
        case ETIMEDOUT:         return "ETIMEDOUT";
        case ETXTBSY:           return "ETXTBSY";
#ifdef EUNATCH
        case EUNATCH:           return "EUNATCH";
#endif
        case EUSERS:            return "EUSERS";
        /* case EWOULDBLOCK:    return "EWOULDBLOCK"; */
        case EXDEV:             return "EXDEV";

#ifdef EBADE // Not available on OS X
        case EBADE:             return "EBADE";
        case EBADFD:            return "EBADFD";
        case EBADSLT:           return "EBADSLT";
        case EDEADLOCK:         return "EDEADLOCK";
        case EBADR:             return "EBADR";
        case EBADRQC:           return "EBADRQC";
        case ECHRNG:            return "ECHRNG";
#ifdef EISNAM // Not available on OS X, Illumos, Solaris
        case EISNAM:            return "EISNAM";
        case EKEYEXPIRED:       return "EKEYEXPIRED";
        case EKEYREVOKED:       return "EKEYREVOKED";
#endif
        case EKEYREJECTED:      return "EKEYREJECTED";
        case EL2HLT:            return "EL2HLT";
        case EL2NSYNC:          return "EL2NSYNC";
        case EL3HLT:            return "EL3HLT";
        case EL3RST:            return "EL3RST";
        case ELIBBAD:           return "ELIBBAD";
        case ELIBMAX:           return "ELIBMAX";
        case ELIBSCN:           return "ELIBSCN";
        case ELIBEXEC:          return "ELIBEXEC";
#ifdef ENOMEDIUM // Not available on OS X, Illumos, Solaris
        case ENOMEDIUM:         return "ENOMEDIUM";
        case EMEDIUMTYPE:       return "EMEDIUMTYPE";
#endif
        case ENONET:            return "ENONET";
        case ENOPKG:            return "ENOPKG";
        case EREMCHG:           return "EREMCHG";
        case ERESTART:          return "ERESTART";
        case ESTRPIPE:          return "ESTRPIPE";
#ifdef EUCLEAN // Not available on OS X, Illumos, Solaris
        case EUCLEAN:           return "EUCLEAN";
#endif
        case EXFULL:            return "EXFULL";
#endif // EBADE
        default:                return "Unknown";
    }
}

/*!
 * \brief Get a user-friendly description of a return code
 *
 * \param[in] rc  Integer return code to convert
 *
 * \return String description of rc
 */
const char *
pcmk_rc_str(int rc)
{
    if (rc == pcmk_rc_ok) {
        return "OK";
    }
    if ((rc <= pcmk_rc_error) && ((pcmk_rc_error - rc) < pcmk__n_rc)) {
        return pcmk__rcs[pcmk_rc_error - rc].desc;
    }
    if (rc < 0) {
        return "Error";
    }

    // Handle values that could be defined by system or by portability.h
    switch (rc) {
#ifdef PCMK__ENOTUNIQ
        case ENOTUNIQ:      return "Name not unique on network";
#endif
#ifdef PCMK__ECOMM
        case ECOMM:         return "Communication error on send";
#endif
#ifdef PCMK__ELIBACC
        case ELIBACC:       return "Can not access a needed shared library";
#endif
#ifdef PCMK__EREMOTEIO
        case EREMOTEIO:     return "Remote I/O error";
#endif
#ifdef PCMK__ENOKEY
        case ENOKEY:        return "Required key not available";
#endif
#ifdef PCMK__ENODATA
        case ENODATA:       return "No data available";
#endif
#ifdef PCMK__ETIME
        case ETIME:         return "Timer expired";
#endif
#ifdef PCMK__EKEYREJECTED
        case EKEYREJECTED:  return "Key was rejected by service";
#endif
        default:            return strerror(rc);
    }
}

// This returns negative values for errors
//! \deprecated Use standard return codes instead
int
pcmk_rc2legacy(int rc)
{
    if (rc >= 0) {
        return -rc; // OK or system errno
    }
    if ((rc <= pcmk_rc_error) && ((pcmk_rc_error - rc) < pcmk__n_rc)) {
        return pcmk__rcs[pcmk_rc_error - rc].legacy_rc;
    }
    return -pcmk_err_generic;
}

//! \deprecated Use standard return codes instead
int
pcmk_legacy2rc(int legacy_rc)
{
    legacy_rc = abs(legacy_rc);
    switch (legacy_rc) {
        case pcmk_err_no_quorum:            return pcmk_rc_no_quorum;
        case pcmk_err_schema_validation:    return pcmk_rc_schema_validation;
        case pcmk_err_schema_unchanged:     return pcmk_rc_schema_unchanged;
        case pcmk_err_transform_failed:     return pcmk_rc_transform_failed;
        case pcmk_err_old_data:             return pcmk_rc_old_data;
        case pcmk_err_diff_failed:          return pcmk_rc_diff_failed;
        case pcmk_err_diff_resync:          return pcmk_rc_diff_resync;
        case pcmk_err_cib_modified:         return pcmk_rc_cib_modified;
        case pcmk_err_cib_backup:           return pcmk_rc_cib_backup;
        case pcmk_err_cib_save:             return pcmk_rc_cib_save;
        case pcmk_err_cib_corrupt:          return pcmk_rc_cib_corrupt;
        case pcmk_err_multiple:             return pcmk_rc_multiple;
        case pcmk_err_node_unknown:         return pcmk_rc_node_unknown;
        case pcmk_err_already:              return pcmk_rc_already;
        case pcmk_err_bad_nvpair:           return pcmk_rc_bad_nvpair;
        case pcmk_err_unknown_format:       return pcmk_rc_unknown_format;
        case pcmk_err_generic:              return pcmk_rc_error;
        case pcmk_ok:                       return pcmk_rc_ok;
        default:                            return legacy_rc; // system errno
    }
}

// Exit status codes

const char *
crm_exit_name(crm_exit_t exit_code)
{
    switch (exit_code) {
        case CRM_EX_OK: return "CRM_EX_OK";
        case CRM_EX_ERROR: return "CRM_EX_ERROR";
        case CRM_EX_INVALID_PARAM: return "CRM_EX_INVALID_PARAM";
        case CRM_EX_UNIMPLEMENT_FEATURE: return "CRM_EX_UNIMPLEMENT_FEATURE";
        case CRM_EX_INSUFFICIENT_PRIV: return "CRM_EX_INSUFFICIENT_PRIV";
        case CRM_EX_NOT_INSTALLED: return "CRM_EX_NOT_INSTALLED";
        case CRM_EX_NOT_CONFIGURED: return "CRM_EX_NOT_CONFIGURED";
        case CRM_EX_NOT_RUNNING: return "CRM_EX_NOT_RUNNING";
        case CRM_EX_PROMOTED: return "CRM_EX_PROMOTED";
        case CRM_EX_FAILED_PROMOTED: return "CRM_EX_FAILED_PROMOTED";
        case CRM_EX_USAGE: return "CRM_EX_USAGE";
        case CRM_EX_DATAERR: return "CRM_EX_DATAERR";
        case CRM_EX_NOINPUT: return "CRM_EX_NOINPUT";
        case CRM_EX_NOUSER: return "CRM_EX_NOUSER";
        case CRM_EX_NOHOST: return "CRM_EX_NOHOST";
        case CRM_EX_UNAVAILABLE: return "CRM_EX_UNAVAILABLE";
        case CRM_EX_SOFTWARE: return "CRM_EX_SOFTWARE";
        case CRM_EX_OSERR: return "CRM_EX_OSERR";
        case CRM_EX_OSFILE: return "CRM_EX_OSFILE";
        case CRM_EX_CANTCREAT: return "CRM_EX_CANTCREAT";
        case CRM_EX_IOERR: return "CRM_EX_IOERR";
        case CRM_EX_TEMPFAIL: return "CRM_EX_TEMPFAIL";
        case CRM_EX_PROTOCOL: return "CRM_EX_PROTOCOL";
        case CRM_EX_NOPERM: return "CRM_EX_NOPERM";
        case CRM_EX_CONFIG: return "CRM_EX_CONFIG";
        case CRM_EX_FATAL: return "CRM_EX_FATAL";
        case CRM_EX_PANIC: return "CRM_EX_PANIC";
        case CRM_EX_DISCONNECT: return "CRM_EX_DISCONNECT";
        case CRM_EX_DIGEST: return "CRM_EX_DIGEST";
        case CRM_EX_NOSUCH: return "CRM_EX_NOSUCH";
        case CRM_EX_QUORUM: return "CRM_EX_QUORUM";
        case CRM_EX_UNSAFE: return "CRM_EX_UNSAFE";
        case CRM_EX_EXISTS: return "CRM_EX_EXISTS";
        case CRM_EX_MULTIPLE: return "CRM_EX_MULTIPLE";
        case CRM_EX_EXPIRED: return "CRM_EX_EXPIRED";
        case CRM_EX_NOT_YET_IN_EFFECT: return "CRM_EX_NOT_YET_IN_EFFECT";
        case CRM_EX_INDETERMINATE: return "CRM_EX_INDETERMINATE";
        case CRM_EX_UNSATISFIED: return "CRM_EX_UNSATISFIED";
        case CRM_EX_NO_DC: return "CRM_EX_NO_DC";
        case CRM_EX_OLD: return "CRM_EX_OLD";
        case CRM_EX_TIMEOUT: return "CRM_EX_TIMEOUT";
        case CRM_EX_DEGRADED: return "CRM_EX_DEGRADED";
        case CRM_EX_DEGRADED_PROMOTED: return "CRM_EX_DEGRADED_PROMOTED";
        case CRM_EX_NONE: return "CRM_EX_NONE";
        case CRM_EX_MAX: return "CRM_EX_UNKNOWN";
    }
    return "CRM_EX_UNKNOWN";
}

const char *
crm_exit_str(crm_exit_t exit_code)
{
    switch (exit_code) {
        case CRM_EX_OK: return "OK";
        case CRM_EX_ERROR: return "Error occurred";
        case CRM_EX_INVALID_PARAM: return "Invalid parameter";
        case CRM_EX_UNIMPLEMENT_FEATURE: return "Unimplemented";
        case CRM_EX_INSUFFICIENT_PRIV: return "Insufficient privileges";
        case CRM_EX_NOT_INSTALLED: return "Not installed";
        case CRM_EX_NOT_CONFIGURED: return "Not configured";
        case CRM_EX_NOT_RUNNING: return "Not running";
        case CRM_EX_PROMOTED: return "Promoted";
        case CRM_EX_FAILED_PROMOTED: return "Failed in promoted role";
        case CRM_EX_USAGE: return "Incorrect usage";
        case CRM_EX_DATAERR: return "Invalid data given";
        case CRM_EX_NOINPUT: return "Input file not available";
        case CRM_EX_NOUSER: return "User does not exist";
        case CRM_EX_NOHOST: return "Host does not exist";
        case CRM_EX_UNAVAILABLE: return "Necessary service unavailable";
        case CRM_EX_SOFTWARE: return "Internal software bug";
        case CRM_EX_OSERR: return "Operating system error occurred";
        case CRM_EX_OSFILE: return "System file not available";
        case CRM_EX_CANTCREAT: return "Cannot create output file";
        case CRM_EX_IOERR: return "I/O error occurred";
        case CRM_EX_TEMPFAIL: return "Temporary failure, try again";
        case CRM_EX_PROTOCOL: return "Protocol violated";
        case CRM_EX_NOPERM: return "Insufficient privileges";
        case CRM_EX_CONFIG: return "Invalid configuration";
        case CRM_EX_FATAL: return "Fatal error occurred, will not respawn";
        case CRM_EX_PANIC: return "System panic required";
        case CRM_EX_DISCONNECT: return "Not connected";
        case CRM_EX_DIGEST: return "Digest mismatch";
        case CRM_EX_NOSUCH: return "No such object";
        case CRM_EX_QUORUM: return "Quorum required";
        case CRM_EX_UNSAFE: return "Operation not safe";
        case CRM_EX_EXISTS: return "Requested item already exists";
        case CRM_EX_MULTIPLE: return "Multiple items match request";
        case CRM_EX_EXPIRED: return "Requested item has expired";
        case CRM_EX_NOT_YET_IN_EFFECT: return "Requested item is not yet in effect";
        case CRM_EX_INDETERMINATE: return "Could not determine status";
        case CRM_EX_UNSATISFIED: return "Not applicable under current conditions";
        case CRM_EX_NO_DC: return "DC is not yet elected";
        case CRM_EX_OLD: return "Update was older than existing configuration";
        case CRM_EX_TIMEOUT: return "Timeout occurred";
        case CRM_EX_DEGRADED: return "Service is active but might fail soon";
        case CRM_EX_DEGRADED_PROMOTED: return "Service is promoted but might fail soon";
        case CRM_EX_NONE: return "No exit status available";
        case CRM_EX_MAX: return "Error occurred";
    }
    if ((exit_code > 128) && (exit_code < CRM_EX_MAX)) {
        return "Interrupted by signal";
    }
    return "Unknown exit status";
}

/*!
 * \brief Map a function return code to the most similar exit code
 *
 * \param[in] rc  Function return code
 *
 * \return Most similar exit code
 */
crm_exit_t
pcmk_rc2exitc(int rc)
{
    switch (rc) {
        case pcmk_rc_ok:
        case pcmk_rc_no_output: // quiet mode, or nothing to output
            return CRM_EX_OK;

        case pcmk_rc_no_quorum:
            return CRM_EX_QUORUM;

        case pcmk_rc_old_data:
            return CRM_EX_OLD;

        case pcmk_rc_cib_corrupt:
        case pcmk_rc_schema_validation:
        case pcmk_rc_transform_failed:
        case pcmk_rc_unpack_error:
            return CRM_EX_CONFIG;

        case pcmk_rc_bad_nvpair:
            return CRM_EX_INVALID_PARAM;

        case EACCES:
            return CRM_EX_INSUFFICIENT_PRIV;

        case EBADF:
        case EINVAL:
        case EFAULT:
        case ENOSYS:
        case EOVERFLOW:
        case pcmk_rc_underflow:
        case pcmk_rc_compression:
            return CRM_EX_SOFTWARE;

        case EBADMSG:
        case EMSGSIZE:
        case ENOMSG:
        case ENOPROTOOPT:
        case EPROTO:
        case EPROTONOSUPPORT:
        case EPROTOTYPE:
            return CRM_EX_PROTOCOL;

        case ECOMM:
        case ENOMEM:
            return CRM_EX_OSERR;

        case ECONNABORTED:
        case ECONNREFUSED:
        case ECONNRESET:
        case ENOTCONN:
            return CRM_EX_DISCONNECT;

        case EEXIST:
        case pcmk_rc_already:
            return CRM_EX_EXISTS;

        case EIO:
        case pcmk_rc_dot_error:
        case pcmk_rc_graph_error:
            return CRM_EX_IOERR;

        case ENOTSUP:
#if EOPNOTSUPP != ENOTSUP
        case EOPNOTSUPP:
#endif
            return CRM_EX_UNIMPLEMENT_FEATURE;

        case ENOTUNIQ:
        case pcmk_rc_multiple:
            return CRM_EX_MULTIPLE;

        case ENODEV:
        case ENOENT:
        case ENXIO:
        case pcmk_rc_no_transaction:
        case pcmk_rc_unknown_format:
            return CRM_EX_NOSUCH;

        case pcmk_rc_node_unknown:
        case pcmk_rc_ns_resolution:
            return CRM_EX_NOHOST;

        case ETIME:
        case ETIMEDOUT:
            return CRM_EX_TIMEOUT;

        case EAGAIN:
        case EBUSY:
            return CRM_EX_UNSATISFIED;

        case pcmk_rc_before_range:
            return CRM_EX_NOT_YET_IN_EFFECT;

        case pcmk_rc_after_range:
            return CRM_EX_EXPIRED;

        case pcmk_rc_undetermined:
            return CRM_EX_INDETERMINATE;

        case pcmk_rc_op_unsatisfied:
            return CRM_EX_UNSATISFIED;

        case pcmk_rc_within_range:
            return CRM_EX_OK;

        case pcmk_rc_no_input:
            return CRM_EX_NOINPUT;

        case pcmk_rc_duplicate_id:
            return CRM_EX_MULTIPLE;

        case pcmk_rc_bad_input:
        case pcmk_rc_bad_xml_patch:
            return CRM_EX_DATAERR;

        case pcmk_rc_no_dc:
            return CRM_EX_NO_DC;

        default:
            return CRM_EX_ERROR;
    }
}

/*!
 * \brief Map a function return code to the most similar OCF exit code
 *
 * \param[in] rc  Function return code
 *
 * \return Most similar OCF exit code
 */
enum ocf_exitcode
pcmk_rc2ocf(int rc)
{
    switch (rc) {
        case pcmk_rc_ok:
            return PCMK_OCF_OK;

        case pcmk_rc_bad_nvpair:
            return PCMK_OCF_INVALID_PARAM;

        case EACCES:
            return PCMK_OCF_INSUFFICIENT_PRIV;

        case ENOTSUP:
#if EOPNOTSUPP != ENOTSUP
        case EOPNOTSUPP:
#endif
            return PCMK_OCF_UNIMPLEMENT_FEATURE;

        default:
            return PCMK_OCF_UNKNOWN_ERROR;
    }
}


// Other functions

/*!
 * \brief Map a getaddrinfo() return code to the most similar Pacemaker
 *        return code
 *
 * \param[in] gai  getaddrinfo() return code
 *
 * \return Most similar Pacemaker return code
 */
int
pcmk__gaierror2rc(int gai)
{
    switch (gai) {
        case 0:
            return pcmk_rc_ok;

        case EAI_AGAIN:
            return EAGAIN;

        case EAI_BADFLAGS:
        case EAI_SERVICE:
            return EINVAL;

        case EAI_FAMILY:
            return EAFNOSUPPORT;

        case EAI_MEMORY:
            return ENOMEM;

        case EAI_NONAME:
            return pcmk_rc_node_unknown;

        case EAI_SOCKTYPE:
            return ESOCKTNOSUPPORT;

        case EAI_SYSTEM:
            return errno;

        default:
            return pcmk_rc_ns_resolution;
    }
}

/*!
 * \brief Map a bz2 return code to the most similar Pacemaker return code
 *
 * \param[in] bz2  bz2 return code
 *
 * \return Most similar Pacemaker return code
 */
int
pcmk__bzlib2rc(int bz2)
{
    switch (bz2) {
        case BZ_OK:
        case BZ_RUN_OK:
        case BZ_FLUSH_OK:
        case BZ_FINISH_OK:
        case BZ_STREAM_END:
            return pcmk_rc_ok;

        case BZ_MEM_ERROR:
            return ENOMEM;

        case BZ_DATA_ERROR:
        case BZ_DATA_ERROR_MAGIC:
        case BZ_UNEXPECTED_EOF:
            return pcmk_rc_bad_input;

        case BZ_IO_ERROR:
            return EIO;

        case BZ_OUTBUFF_FULL:
            return EFBIG;

        default:
            return pcmk_rc_compression;
    }
}

crm_exit_t
crm_exit(crm_exit_t exit_status)
{
    /* A compiler could theoretically use any type for crm_exit_t, but an int
     * should always hold it, so cast to int to keep static analysis happy.
     */
    if ((((int) exit_status) < 0) || (((int) exit_status) > CRM_EX_MAX)) {
        exit_status = CRM_EX_ERROR;
    }

    crm_info("Exiting %s " QB_XS " with status %d (%s: %s)",
             pcmk__s(crm_system_name, "process"), exit_status,
             crm_exit_name(exit_status), crm_exit_str(exit_status));
    pcmk_common_cleanup();
    exit(exit_status);
}

/*
 * External action results
 */

/*!
 * \internal
 * \brief Set the result of an action
 *
 * \param[out] result        Where to set action result
 * \param[in]  exit_status   OCF exit status to set
 * \param[in]  exec_status   Execution status to set
 * \param[in]  exit_reason   Human-friendly description of event to set
 */
void
pcmk__set_result(pcmk__action_result_t *result, int exit_status,
                 enum pcmk_exec_status exec_status, const char *exit_reason)
{
    if (result == NULL) {
        return;
    }

    result->exit_status = exit_status;
    result->execution_status = exec_status;

    if (!pcmk__str_eq(result->exit_reason, exit_reason, pcmk__str_none)) {
        free(result->exit_reason);
        result->exit_reason = (exit_reason == NULL)? NULL : strdup(exit_reason);
    }
}


/*!
 * \internal
 * \brief Set the result of an action, with a formatted exit reason
 *
 * \param[out] result        Where to set action result
 * \param[in]  exit_status   OCF exit status to set
 * \param[in]  exec_status   Execution status to set
 * \param[in]  format        printf-style format for a human-friendly
 *                           description of reason for result
 * \param[in]  ...           arguments for \p format
 */
G_GNUC_PRINTF(4, 5)
void
pcmk__format_result(pcmk__action_result_t *result, int exit_status,
                    enum pcmk_exec_status exec_status,
                    const char *format, ...)
{
    va_list ap;
    int len = 0;
    char *reason = NULL;

    if (result == NULL) {
        return;
    }

    result->exit_status = exit_status;
    result->execution_status = exec_status;

    if (format != NULL) {
        va_start(ap, format);
        len = vasprintf(&reason, format, ap);
        pcmk__assert(len > 0);
        va_end(ap);
    }
    free(result->exit_reason);
    result->exit_reason = reason;
}

/*!
 * \internal
 * \brief Set the output of an action
 *
 * \param[out] result         Action result to set output for
 * \param[in]  out            Action output to set (must be dynamically
 *                            allocated)
 * \param[in]  err            Action error output to set (must be dynamically
 *                            allocated)
 *
 * \note \p result will take ownership of \p out and \p err, so the caller
 *       should not free them.
 */
void
pcmk__set_result_output(pcmk__action_result_t *result, char *out, char *err)
{
    if (result == NULL) {
        return;
    }

    free(result->action_stdout);
    result->action_stdout = out;

    free(result->action_stderr);
    result->action_stderr = err;
}

/*!
 * \internal
 * \brief Clear a result's exit reason, output, and error output
 *
 * \param[in,out] result  Result to reset
 */
void
pcmk__reset_result(pcmk__action_result_t *result)
{
    if (result == NULL) {
        return;
    }

    free(result->exit_reason);
    result->exit_reason = NULL;

    free(result->action_stdout);
    result->action_stdout = NULL;

    free(result->action_stderr);
    result->action_stderr = NULL;
}

/*!
 * \internal
 * \brief Copy the result of an action
 *
 * \param[in]  src  Result to copy
 * \param[out] dst  Where to copy \p src to
 */
void
pcmk__copy_result(const pcmk__action_result_t *src, pcmk__action_result_t *dst)
{
    CRM_CHECK((src != NULL) && (dst != NULL), return);
    dst->exit_status = src->exit_status;
    dst->execution_status = src->execution_status;
    dst->exit_reason = pcmk__str_copy(src->exit_reason);
    dst->action_stdout = pcmk__str_copy(src->action_stdout);
    dst->action_stderr = pcmk__str_copy(src->action_stderr);
}
