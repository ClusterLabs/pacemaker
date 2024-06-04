/*
 * Copyright 2001-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__PORTABILITY__H
#  define PCMK__PORTABILITY__H

/* This header provides replacements for required definitions and declarations
 * that certain supported build environments don't provide
 */

/* This header *MUST* be included before any system headers, because the
 * following definition can change the behavior of some of them.
 */
#  undef _GNU_SOURCE            /* in case it was defined on the command line */
#  define _GNU_SOURCE

/* Please leave this as the first #include - Solaris needs it there */
#  ifdef HAVE_CONFIG_H
#    ifndef PCMK__CONFIG_H
#      define PCMK__CONFIG_H
#      include <config.h>
#    endif
#  endif

// Replacement constants for Linux-specific errno values

#  include <errno.h>

#  ifndef ENOTUNIQ
#    define PCMK__ENOTUNIQ
#    define ENOTUNIQ  190
#  endif

#  ifndef ECOMM
#    define PCMK__ECOMM
#    define ECOMM     191
#  endif

#  ifndef ELIBACC
#    define PCMK__ELIBACC
#    define ELIBACC   192
#  endif

#  ifndef EREMOTEIO
#    define PCMK__EREMOTIO
#    define EREMOTEIO 193
#  endif

#  ifndef ENOKEY
#    define PCMK__ENOKEY
#    define ENOKEY    195
#  endif

#  ifndef ENODATA
#    define PCMK__ENODATA
#    define ENODATA   196
#  endif

#  ifndef ETIME
#    define PCMK__ETIME
#    define ETIME     197
#  endif

#  ifndef EKEYREJECTED
#    define PCMK__EKEYREJECTED
#    define EKEYREJECTED 200
#  endif

#endif // PCMK__PORTABILITY__H
