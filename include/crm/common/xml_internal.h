/*
 * Copyright 2017 Jan Pokorny <jpokorny@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_COMMON_XML_INTERNAL__H
#  define CRM_COMMON_XML_INTERNAL__H

/*
 * Internal-only wrappers for and extensions to libxml2 (libxslt)
 */

#  include <stdlib.h>
#  include <stdio.h>
#  include <string.h>

#  include <crm/crm.h>  /* transitively imports qblog.h */


/*!
 * \brief Base for directing lib{xml2,xslt} log into standard libqb backend
 *
 * This macro implements the core of what can be needed for directing
 * libxml2 or libxslt error messaging into standard, preconfigured
 * libqb-backed log stream.
 *
 * It's a bit unfortunate that libxml2 (and more sparsely, also libxslt)
 * emits a single message by chunks (location is emitted separatedly from
 * the message itself), so we have to take the effort to combine these
 * chunks back to single message.  Whether to do this or not is driven
 * with \p dechunk toggle.
 *
 * The form of a macro was chosen for implicit deriving of __FILE__, etc.
 * and also because static dechunking buffer should be differentiated per
 * library (here we assume different functions referring to this macro
 * will not ever be using both at once), preferably also per-library
 * context of use to avoid clashes altogether.
 *
 * Note that we cannot use qb_logt, because callsite data have to be known
 * at the moment of compilation, which it is not always the case -- xml_log
 * (and unfortunately there's no clear explanation of the fail to compile).
 *
 * Also note that there's no explicit guard against said libraries producing
 * never-newline-terminated chunks (which would just keep consuming memory),
 * as it's quite improbable.  Termination of the program in between the
 * same-message chunks will raise a flag with valgrind and the likes, though.
 *
 * And lastly, regarding how dechunking combines with other non-message
 * parameters -- for \p priority, most important running specification
 * wins (possibly elevated to LOG_ERR in case of nonconformance with the
 * newline-termination "protocol"), \p dechunk is expected to always be
 * on once it was at the start, and the rest (\p postemit and \p prefix)
 * are picked directly from the last chunk entry finalizing the message
 * (also reasonable to always have it the same with all related entries).
 *
 * \param[in] priority Syslog priority for the message to be logged
 * \param[in] dechunk  Whether to dechunk new-line terminated message
 * \param[in] postemit Code to be executed once message is sent out
 * \param[in] prefix   How to prefix the message or NULL for raw passing
 * \param[in] fmt      Format string as with printf-like functions
 * \param[in] ap       Variable argument list to supplement \p fmt format string
 */
#define CRM_XML_LOG_BASE(priority, dechunk, postemit, prefix, fmt, ap)          \
do {                                                                            \
    if (!(dechunk) && (prefix) == NULL) {  /* quick pass */                     \
        qb_log_from_external_source_va(__FUNCTION__, __FILE__, (fmt),           \
                                       (priority), __LINE__, 0, (ap));          \
        (void) (postemit);                                                      \
    } else {                                                                    \
        int CXLB_len = 0;                                                       \
        char *CXLB_buf = NULL;                                                  \
        static int CXLB_buffer_len = 0;                                         \
        static char *CXLB_buffer = NULL;                                        \
        static uint8_t CXLB_priority = 0;                                       \
                                                                                \
        CXLB_len = vasprintf(&CXLB_buf, (fmt), (ap));                           \
                                                                                \
        if (CXLB_len <= 0 || CXLB_buf[CXLB_len - 1] == '\n' || !(dechunk)) {    \
            if (CXLB_len < 0) {                                                 \
                CXLB_buf = (char *) "LOG CORRUPTION HAZARD"; /*we don't modify*/\
                CXLB_priority = QB_MIN(CXLB_priority, LOG_ERR);                 \
            } else if (CXLB_len > 0 /* && (dechunk) */                          \
                       && CXLB_buf[CXLB_len - 1] == '\n') {                     \
                CXLB_buf[CXLB_len - 1] = '\0';                                  \
            }                                                                   \
            if (CXLB_buffer) {                                                  \
                qb_log_from_external_source(__FUNCTION__, __FILE__, "%s%s%s",   \
                                            CXLB_priority, __LINE__, 0,         \
                                            (prefix) != NULL ? (prefix) : "",   \
                                            CXLB_buffer, CXLB_buf);             \
                free(CXLB_buffer);                                              \
            } else {                                                            \
                qb_log_from_external_source(__FUNCTION__, __FILE__, "%s%s",     \
                                            (priority), __LINE__, 0,            \
                                            (prefix) != NULL ? (prefix) : "",   \
                                            CXLB_buf);                          \
            }                                                                   \
            if (CXLB_len < 0) {                                                 \
                CXLB_buf = NULL;  /* restore temporary override */              \
            }                                                                   \
            CXLB_buffer = NULL;                                                 \
            CXLB_buffer_len = 0;                                                \
            (void) (postemit);                                                  \
                                                                                \
        } else if (CXLB_buffer == NULL) {                                       \
            CXLB_buffer_len = CXLB_len;                                         \
            CXLB_buffer = CXLB_buf;                                             \
            CXLB_buf = NULL;                                                    \
            CXLB_priority = (priority);  /* remember as a running severest */   \
                                                                                \
        } else {                                                                \
            CXLB_buffer = realloc(CXLB_buffer, 1 + CXLB_buffer_len + CXLB_len); \
            memcpy(CXLB_buffer + CXLB_buffer_len, CXLB_buf, CXLB_len);          \
            CXLB_buffer_len += CXLB_len;                                        \
            CXLB_buffer[CXLB_buffer_len] = '\0';                                \
            CXLB_priority = QB_MIN(CXLB_priority, (priority));  /* severest? */ \
        }                                                                       \
        free(CXLB_buf);                                                         \
    }                                                                           \
} while (0)

#endif
