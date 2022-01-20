/*
 * Copyright 2007-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__PCMKI_PCMKI_ERROR__H
#  define  PCMK__PCMKI_PCMKI_ERROR__H

#define CMD_ERR(fmt, args...) do {              \
            crm_warn(fmt, ##args);              \
            fprintf(stderr, fmt "\n", ##args);  \
        } while(0)

#endif
