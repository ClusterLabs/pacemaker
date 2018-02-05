/*
 * Copyright (C) 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+)WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <bzlib.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <qb/qbdefs.h>

#include <crm/common/mainloop.h>
#include <crm/common/xml.h>

const char *
pcmk_errorname(int rc)
{
    int error = abs(rc);

    switch (error) {
        case E2BIG: return "E2BIG";
        case EACCES: return "EACCES";
        case EADDRINUSE: return "EADDRINUSE";
        case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
        case EAFNOSUPPORT: return "EAFNOSUPPORT";
        case EAGAIN: return "EAGAIN";
        case EALREADY: return "EALREADY";
        case EBADF: return "EBADF";
        case EBADMSG: return "EBADMSG";
        case EBUSY: return "EBUSY";
        case ECANCELED: return "ECANCELED";
        case ECHILD: return "ECHILD";
        case ECOMM: return "ECOMM";
        case ECONNABORTED: return "ECONNABORTED";
        case ECONNREFUSED: return "ECONNREFUSED";
        case ECONNRESET: return "ECONNRESET";
        /* case EDEADLK: return "EDEADLK"; */
        case EDESTADDRREQ: return "EDESTADDRREQ";
        case EDOM: return "EDOM";
        case EDQUOT: return "EDQUOT";
        case EEXIST: return "EEXIST";
        case EFAULT: return "EFAULT";
        case EFBIG: return "EFBIG";
        case EHOSTDOWN: return "EHOSTDOWN";
        case EHOSTUNREACH: return "EHOSTUNREACH";
        case EIDRM: return "EIDRM";
        case EILSEQ: return "EILSEQ";
        case EINPROGRESS: return "EINPROGRESS";
        case EINTR: return "EINTR";
        case EINVAL: return "EINVAL";
        case EIO: return "EIO";
        case EISCONN: return "EISCONN";
        case EISDIR: return "EISDIR";
        case ELIBACC: return "ELIBACC";
        case ELOOP: return "ELOOP";
        case EMFILE: return "EMFILE";
        case EMLINK: return "EMLINK";
        case EMSGSIZE: return "EMSGSIZE";
        case EMULTIHOP: return "EMULTIHOP";
        case ENAMETOOLONG: return "ENAMETOOLONG";
        case ENETDOWN: return "ENETDOWN";
        case ENETRESET: return "ENETRESET";
        case ENETUNREACH: return "ENETUNREACH";
        case ENFILE: return "ENFILE";
        case ENOBUFS: return "ENOBUFS";
        case ENODATA: return "ENODATA";
        case ENODEV: return "ENODEV";
        case ENOENT: return "ENOENT";
        case ENOEXEC: return "ENOEXEC";
        case ENOKEY: return "ENOKEY";
        case ENOLCK: return "ENOLCK";
        case ENOLINK: return "ENOLINK";
        case ENOMEM: return "ENOMEM";
        case ENOMSG: return "ENOMSG";
        case ENOPROTOOPT: return "ENOPROTOOPT";
        case ENOSPC: return "ENOSPC";
        case ENOSR: return "ENOSR";
        case ENOSTR: return "ENOSTR";
        case ENOSYS: return "ENOSYS";
        case ENOTBLK: return "ENOTBLK";
        case ENOTCONN: return "ENOTCONN";
        case ENOTDIR: return "ENOTDIR";
        case ENOTEMPTY: return "ENOTEMPTY";
        case ENOTSOCK: return "ENOTSOCK";
        /* case ENOTSUP: return "ENOTSUP"; */
        case ENOTTY: return "ENOTTY";
        case ENOTUNIQ: return "ENOTUNIQ";
        case ENXIO: return "ENXIO";
        case EOPNOTSUPP: return "EOPNOTSUPP";
        case EOVERFLOW: return "EOVERFLOW";
        case EPERM: return "EPERM";
        case EPFNOSUPPORT: return "EPFNOSUPPORT";
        case EPIPE: return "EPIPE";
        case EPROTO: return "EPROTO";
        case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
        case EPROTOTYPE: return "EPROTOTYPE";
        case ERANGE: return "ERANGE";
        case EREMOTE: return "EREMOTE";
        case EREMOTEIO: return "EREMOTEIO";

        case EROFS: return "EROFS";
        case ESHUTDOWN: return "ESHUTDOWN";
        case ESPIPE: return "ESPIPE";
        case ESOCKTNOSUPPORT: return "ESOCKTNOSUPPORT";
        case ESRCH: return "ESRCH";
        case ESTALE: return "ESTALE";
        case ETIME: return "ETIME";
        case ETIMEDOUT: return "ETIMEDOUT";
        case ETXTBSY: return "ETXTBSY";
        case EUNATCH: return "EUNATCH";
        case EUSERS: return "EUSERS";
        /* case EWOULDBLOCK: return "EWOULDBLOCK"; */
        case EXDEV: return "EXDEV";

#ifdef EBADE
            /* Not available on OSX */
        case EBADE: return "EBADE";
        case EBADFD: return "EBADFD";
        case EBADSLT: return "EBADSLT";
        case EDEADLOCK: return "EDEADLOCK";
        case EBADR: return "EBADR";
        case EBADRQC: return "EBADRQC";
        case ECHRNG: return "ECHRNG";
#ifdef EISNAM /* Not available on Illumos/Solaris */
        case EISNAM: return "EISNAM";
        case EKEYEXPIRED: return "EKEYEXPIRED";
        case EKEYREJECTED: return "EKEYREJECTED";
        case EKEYREVOKED: return "EKEYREVOKED";
#endif
        case EL2HLT: return "EL2HLT";
        case EL2NSYNC: return "EL2NSYNC";
        case EL3HLT: return "EL3HLT";
        case EL3RST: return "EL3RST";
        case ELIBBAD: return "ELIBBAD";
        case ELIBMAX: return "ELIBMAX";
        case ELIBSCN: return "ELIBSCN";
        case ELIBEXEC: return "ELIBEXEC";
#ifdef ENOMEDIUM  /* Not available on Illumos/Solaris */
        case ENOMEDIUM: return "ENOMEDIUM";
        case EMEDIUMTYPE: return "EMEDIUMTYPE";
#endif
        case ENONET: return "ENONET";
        case ENOPKG: return "ENOPKG";
        case EREMCHG: return "EREMCHG";
        case ERESTART: return "ERESTART";
        case ESTRPIPE: return "ESTRPIPE";
#ifdef EUCLEAN  /* Not available on Illumos/Solaris */
        case EUCLEAN: return "EUCLEAN";
#endif
        case EXFULL: return "EXFULL";
#endif

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
    }
    return "Unknown";
}

const char *
pcmk_strerror(int rc)
{
    int error = abs(rc);

    if (error == 0) {
        return "OK";
    } else if (error < PCMK_ERROR_OFFSET) {
        return strerror(error);
    }

    switch (error) {
        case pcmk_err_generic:
            return "Generic Pacemaker error";
        case pcmk_err_no_quorum:
            return "Operation requires quorum";
        case pcmk_err_schema_validation:
            return "Update does not conform to the configured schema";
        case pcmk_err_transform_failed:
            return "Schema transform failed";
        case pcmk_err_old_data:
            return "Update was older than existing configuration";
        case pcmk_err_diff_failed:
            return "Application of an update diff failed";
        case pcmk_err_diff_resync:
            return "Application of an update diff failed, requesting a full refresh";
        case pcmk_err_cib_modified:
            return "The on-disk configuration was manually modified";
        case pcmk_err_cib_backup:
            return "Could not archive the previous configuration";
        case pcmk_err_cib_save:
            return "Could not save the new configuration to disk";
        case pcmk_err_cib_corrupt:
            return "Could not parse on-disk configuration";

        case pcmk_err_schema_unchanged:
            return "Schema is already the latest available";

            /* The following cases will only be hit on systems for which they are non-standard */
            /* coverity[dead_error_condition] False positive on non-Linux */
        case ENOTUNIQ:
            return "Name not unique on network";
            /* coverity[dead_error_condition] False positive on non-Linux */
        case ECOMM:
            return "Communication error on send";
            /* coverity[dead_error_condition] False positive on non-Linux */
        case ELIBACC:
            return "Can not access a needed shared library";
            /* coverity[dead_error_condition] False positive on non-Linux */
        case EREMOTEIO:
            return "Remote I/O error";
            /* coverity[dead_error_condition] False positive on non-Linux */
        case EUNATCH:
            return "Protocol driver not attached";
            /* coverity[dead_error_condition] False positive on non-Linux */
        case ENOKEY:
            return "Required key not available";
    }

    crm_err("Unknown error code: %d", rc);
    return "Unknown error";
}

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
        case CRM_EX_OLD: return "CRM_EX_OLD";
        case CRM_EX_TIMEOUT: return "CRM_EX_TIMEOUT";
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
        case CRM_EX_OLD: return "Update was older than existing configuration";
        case CRM_EX_TIMEOUT: return "Timeout occurred";
        case CRM_EX_MAX: return "Error occurred";
    }
    if (exit_code > 128) {
        return "Interrupted by signal";
    }
    return "Unknown exit status";
}

/*!
 * \brief Map an errno to a similar exit status
 *
 * \param[in] errno  Error number to map
 *
 * \return Exit status corresponding to errno
 */
crm_exit_t
crm_errno2exit(int rc)
{
    rc = abs(rc); // Convenience for functions that return -errno
    if (rc == EOPNOTSUPP) {
        rc = ENOTSUP; // Values are same on Linux, can't use both in case
    }
    switch (rc) {
        case pcmk_ok:
            return CRM_EX_OK;

        case pcmk_err_no_quorum:
            return CRM_EX_QUORUM;

        case pcmk_err_old_data:
            return CRM_EX_OLD;

        case pcmk_err_schema_validation:
        case pcmk_err_transform_failed:
            return CRM_EX_CONFIG;

        case EACCES:
            return CRM_EX_INSUFFICIENT_PRIV;

        case EBADF:
        case EINVAL:
        case EFAULT:
        case ENOSYS:
        case EOVERFLOW:
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
            return CRM_EX_EXISTS;

        case EIO:
            return CRM_EX_IOERR;

        case ENOTSUP:
            return CRM_EX_UNIMPLEMENT_FEATURE;

        case ENOTUNIQ:
            return CRM_EX_MULTIPLE;

        case ENXIO:
            return CRM_EX_NOSUCH;

        case ETIME:
        case ETIMEDOUT:
            return CRM_EX_TIMEOUT;

        default:
            return CRM_EX_ERROR;
    }
}

const char *
bz2_strerror(int rc)
{
    /* http://www.bzip.org/1.0.3/html/err-handling.html */
    switch (rc) {
        case BZ_OK:
        case BZ_RUN_OK:
        case BZ_FLUSH_OK:
        case BZ_FINISH_OK:
        case BZ_STREAM_END:
            return "Ok";
        case BZ_CONFIG_ERROR:
            return "libbz2 has been improperly compiled on your platform";
        case BZ_SEQUENCE_ERROR:
            return "library functions called in the wrong order";
        case BZ_PARAM_ERROR:
            return "parameter is out of range or otherwise incorrect";
        case BZ_MEM_ERROR:
            return "memory allocation failed";
        case BZ_DATA_ERROR:
            return "data integrity error is detected during decompression";
        case BZ_DATA_ERROR_MAGIC:
            return "the compressed stream does not start with the correct magic bytes";
        case BZ_IO_ERROR:
            return "error reading or writing in the compressed file";
        case BZ_UNEXPECTED_EOF:
            return "compressed file finishes before the logical end of stream is detected";
        case BZ_OUTBUFF_FULL:
            return "output data will not fit into the buffer provided";
    }
    return "Unknown error";
}

crm_exit_t
crm_exit(crm_exit_t rc)
{
    CRM_CHECK((rc >= 0) && (rc <= 255), rc = CRM_EX_ERROR);

    mainloop_cleanup();
    crm_xml_cleanup();

    qb_log_fini();
    crm_args_fini();

    if (crm_system_name) {
        crm_info("Exiting %s " CRM_XS " with status %d", crm_system_name, rc);
        free(crm_system_name);
    } else {
        crm_trace("Exiting with status %d", rc);
    }

    exit(rc);
    return rc;     /* Can never happen, but allows return crm_exit(rc)
                    * where "return rc" was used previously - which
                    * keeps compilers happy.
                    */
}
