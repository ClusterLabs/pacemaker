/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* A collection of items that needs to be made public by openais */

typedef struct {
	int size __attribute__((aligned(8)));
	int id __attribute__((aligned(8)));
} mar_req_header_t __attribute__((aligned(8)));

enum service_types {
	EVS_SERVICE = 0,
	CLM_SERVICE = 1,
	AMF_SERVICE = 2,
	CKPT_SERVICE = 3,
	EVT_SERVICE = 4,
	LCK_SERVICE = 5,
	MSG_SERVICE = 6,
	CFG_SERVICE = 7,
	CPG_SERVICE = 8
};
