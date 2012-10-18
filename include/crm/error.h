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

/**
 * \file
 * \brief Error codes and asserts
 * \ingroup core
 */

/*
  System error codes
  - /usr/include/asm-generic/errno.h
  - /usr/include/asm-generic/errno-base.h
*/

#  define CRM_ASSERT(expr) do {						\
	if(__unlikely((expr) == FALSE)) {				\
	    crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, #expr, TRUE, FALSE); \
	}								\
    } while(0)

#  define pcmk_ok                       0
#  define PCMK_ERROR_OFFSET             900  /* Replacements on non-linux systems, see include/portability.h */ 
#  define PCMK_CUSTOM_OFFSET            1000 /* Purely custom codes */
#  define pcmk_err_generic              1001
#  define pcmk_err_no_quorum            1002
#  define pcmk_err_dtd_validation       1003
#  define pcmk_err_transform_failed     1004
#  define pcmk_err_old_data             1005
#  define pcmk_err_diff_failed          1006
#  define pcmk_err_diff_resync          1007

const char *pcmk_strerror(int rc);

#endif
