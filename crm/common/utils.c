/* $Id: utils.c,v 1.1 2004/06/02 11:45:28 andrew Exp $ */
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
#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>

#include <clplumbing/cl_log.h>

#include <time.h> 

#include <clplumbing/Gmain_timeout.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/dmalloc_wrapper.h>


static uint ref_counter = 0;

const char *
generateReference(const char *custom1, const char *custom2)
{

	const char *local_cust1 = custom1;
	const char *local_cust2 = custom2;
	int reference_len = 4;
	char *since_epoch = NULL;

	FNIN();
	
	reference_len += 20; // too big
	reference_len += 40; // too big
	
	if(local_cust1 == NULL) local_cust1 = "_empty_";
	reference_len += strlen(local_cust1);
	
	if(local_cust2 == NULL) local_cust2 = "_empty_";
	reference_len += strlen(local_cust2);
	
	since_epoch = (char*)crm_malloc(reference_len*(sizeof(char)));
	FNIN();
	sprintf(since_epoch, "%s-%s-%ld-%u",
		local_cust1, local_cust2,
		(unsigned long)time(NULL), ref_counter++);

	FNRET(since_epoch);
}

gboolean
decodeNVpair(const char *srcstring, char separator, char **name, char **value)
{
	int lpc = 0;
	int len = 0;
	const char *temp = NULL;

	FNIN();

	CRM_DEBUG("Attempting to decode: [%s]", srcstring);
	if (srcstring != NULL) {
		len = strlen(srcstring);
		while(lpc < len) {
			if (srcstring[lpc++] == separator) {
				*name = (char*)crm_malloc(sizeof(char)*lpc);
				strncpy(*name, srcstring, lpc-1);
				(*name)[lpc-1] = '\0';

				// this sucks but as the strtok *is* a bug
				len = len-lpc+1;
				*value = (char*)crm_malloc(sizeof(char)*len);
				temp = srcstring+lpc;
				strncpy(*value, temp, len-1);
				(*value)[len-1] = '\0';

				FNRET(TRUE);
			}
		}
	}

	*name = NULL;
	*value = NULL;
    
	FNRET(FALSE);
}

char *
generate_hash_key(const char *crm_msg_reference, const char *sys)
{
	int ref_len = strlen(sys?sys:"none") + strlen(crm_msg_reference) + 2;
	char *hash_key = (char*)crm_malloc(sizeof(char)*(ref_len));

	FNIN();
	sprintf(hash_key, "%s_%s", sys?sys:"none", crm_msg_reference);
	hash_key[ref_len-1] = '\0';
	cl_log(LOG_INFO, "created hash key: (%s)", hash_key);
	FNRET(hash_key);
}

char *
generate_hash_value(const char *src_node, const char *src_subsys)
{
	int ref_len;
	char *hash_value;

	FNIN();
	if (src_node == NULL || src_subsys == NULL) {
		FNRET(NULL);
	}
    
	if (strcmp(CRM_SYSTEM_DC, src_subsys) == 0) {
		hash_value = crm_strdup(src_subsys);
		if (!hash_value) {
			cl_log(LOG_ERR,
			       "memory allocation failed in "
			       "generate_hash_value()\n");
			FNRET(NULL);
		}
		FNRET(hash_value);
	}
    
	ref_len = strlen(src_subsys) + strlen(src_node) + 2;
	hash_value = (char*)crm_malloc(sizeof(char)*(ref_len));
	if (!hash_value) {
		cl_log(LOG_ERR,
		       "memory allocation failed in "
		       "generate_hash_value()\n");
		FNRET(NULL);
	}

	snprintf(hash_value, ref_len-1, "%s_%s", src_node, src_subsys);
	hash_value[ref_len-1] = '\0';// make sure it is null terminated

	cl_log(LOG_INFO, "created hash value: (%s)", hash_value);
	FNRET(hash_value);
}

gboolean
decode_hash_value(gpointer value, char **node, char **subsys)
{
	char *char_value = (char*)value;
	int value_len = strlen(char_value);

	FNIN();
    
	cl_log(LOG_INFO, "Decoding hash value: (%s:%d)",
	       char_value,
	       value_len);
    	
	if (strcmp(CRM_SYSTEM_DC, (char*)value) == 0) {
		*node = NULL;
		*subsys = (char*)crm_strdup(char_value);
		if (!*subsys) {
			cl_log(LOG_ERR, "memory allocation failed in "
			       "decode_hash_value()\n");
			FNRET(FALSE);
		}
		cl_log(LOG_INFO, "Decoded value: (%s:%d)", *subsys, 
		       (int)strlen(*subsys));
		FNRET(TRUE);
	}
	else if (char_value != NULL) {
		if (decodeNVpair(char_value, '_', node, subsys)) {
			FNRET(TRUE);
		} else {
			*node = NULL;
			*subsys = NULL;
			FNRET(FALSE);
		}
	}
	FNRET(FALSE);
}


char *
crm_itoa(int an_int)
{
	int len = 32;
	char *buffer = crm_malloc(sizeof(char)*(len+1));
	snprintf(buffer, len, "%d", an_int);

	return buffer;
}
