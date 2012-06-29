/* 
 * Copyright (C) 2012 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_ERROR__H
#  define CRM_ERROR__H
#  include <crm_config.h>
#  include <assert.h>

#  define CRM_ASSERT(expr) do {						\
	if(__unlikely((expr) == FALSE)) {				\
	    crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, #expr, TRUE, FALSE); \
	}								\
    } while(0)

#  define pcmk_ok                       0
#  define PCMK_ERROR_OFFSET             1000
#  define pcmk_err_generic              1001
#  define pcmk_err_no_quorum            1002
#  define pcmk_err_dtd_validation       1003
#  define pcmk_err_transform_failed     1004
#  define pcmk_err_old_data             1005
#  define pcmk_err_diff_failed          1006
#  define pcmk_err_diff_resync          1007

static inline const char *
pcmk_strerror(int rc)
{
    int error = rc;
    if(rc < 0) {
        error = 0 - rc;
    }

    if(error == 0) {
        return "OK";
    } else if(error < PCMK_ERROR_OFFSET) {
        return strerror(error);
    }

    switch(error) {
        case pcmk_err_generic:
            return "Generic error";
        case pcmk_err_no_quorum:
            return "Operation requires quorum";
        case pcmk_err_dtd_validation:
            return "Update does not conform to the configured schema";
        case pcmk_err_transform_failed:
            return "Schema transform failed";
        case pcmk_err_old_data:
            return "Update was older than existing configuration";
        case pcmk_err_diff_failed:
            return "Application of an update diff failed";
        case pcmk_err_diff_resync:
            return "Application of an update diff failed, requesting a full refresh";
    }

    crm_err("Unknown error code: %d", rc);
    return "Unknown error";
}

#endif
