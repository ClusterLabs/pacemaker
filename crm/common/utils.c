/* $Id: utils.c,v 1.26 2005/02/07 11:13:07 andrew Exp $ */
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

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>


#include <ha_msg.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>

#include <time.h> 

#include <clplumbing/Gmain_timeout.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/dmalloc_wrapper.h>

#define MAXLINE 512

static uint ref_counter = 0;

char *
generateReference(const char *custom1, const char *custom2)
{

	const char *local_cust1 = custom1;
	const char *local_cust2 = custom2;
	int reference_len = 4;
	char *since_epoch = NULL;

	
	
	reference_len += 20; /* too big */
	reference_len += 40; /* too big */
	
	if(local_cust1 == NULL) local_cust1 = "_empty_";
	reference_len += strlen(local_cust1);
	
	if(local_cust2 == NULL) local_cust2 = "_empty_";
	reference_len += strlen(local_cust2);
	
	crm_malloc(since_epoch, reference_len*(sizeof(char)));

	if(since_epoch != NULL) {
		sprintf(since_epoch, "%s-%s-%ld-%u",
			local_cust1, local_cust2,
			(unsigned long)time(NULL), ref_counter++);
	}

	return since_epoch;
}

gboolean
decodeNVpair(const char *srcstring, char separator, char **name, char **value)
{
	int lpc = 0;
	int len = 0;
	const char *temp = NULL;

	crm_trace("Attempting to decode: [%s]", srcstring);
	if (srcstring != NULL) {
		len = strlen(srcstring);
		while(lpc <= len) {
			if (srcstring[lpc] == separator
			    || srcstring[lpc] == '\0') {
				crm_malloc(*name, sizeof(char)*lpc+1);
				if(*name == NULL) {
					break; /* and return FALSE */
				}
				strncpy(*name, srcstring, lpc);
				(*name)[lpc] = '\0';

/* this sucks but as the strtok manpage says..
 * it *is* a bug
 */
				len = len-lpc; len--;
				if(len <= 0) {
					*value = NULL;
				} else {

					crm_malloc(*value, sizeof(char)*len+1);
					if(*value == NULL) {
						crm_free(*name);
						break; /* and return FALSE */
					}
					temp = srcstring+lpc+1;
					strncpy(*value, temp, len);
					(*value)[len] = '\0';
				}

				return TRUE;
			}
			lpc++;
		}
	}

	*name = NULL;
	*value = NULL;
    
	return FALSE;
}

char *
generate_hash_key(const char *crm_msg_reference, const char *sys)
{
	int ref_len = strlen(sys?sys:"none") + strlen(crm_msg_reference) + 2;
	char *hash_key = NULL;
	crm_malloc(hash_key, sizeof(char)*(ref_len));

	if(hash_key != NULL) {
		sprintf(hash_key, "%s_%s", sys?sys:"none", crm_msg_reference);
		hash_key[ref_len-1] = '\0';
		crm_debug("created hash key: (%s)", hash_key);
	}
	return hash_key;
}

char *
generate_hash_value(const char *src_node, const char *src_subsys)
{
	int ref_len;
	char *hash_value;
	
	if (src_node == NULL || src_subsys == NULL) {
		return NULL;
	}
    
	if (strcmp(CRM_SYSTEM_DC, src_subsys) == 0) {
		hash_value = crm_strdup(src_subsys);
		if (!hash_value) {
			crm_err("memory allocation failed in "
			       "generate_hash_value()\n");
			return NULL;
		}
		return hash_value;
	}
    
	ref_len = strlen(src_subsys) + strlen(src_node) + 2;
	crm_malloc(hash_value, sizeof(char)*(ref_len));
	if (!hash_value) {
		crm_err("memory allocation failed in "
		       "generate_hash_value()\n");
		return NULL;
	}

	snprintf(hash_value, ref_len-1, "%s_%s", src_node, src_subsys);
	hash_value[ref_len-1] = '\0';/* make sure it is null terminated */

	crm_info("created hash value: (%s)", hash_value);
	return hash_value;
}

gboolean
decode_hash_value(gpointer value, char **node, char **subsys)
{
	char *char_value = (char*)value;
	int value_len = strlen(char_value);

	crm_info("Decoding hash value: (%s:%d)", char_value, value_len);
    	
	if (strcmp(CRM_SYSTEM_DC, (char*)value) == 0) {
		*node = NULL;
		*subsys = (char*)crm_strdup(char_value);
		if (*subsys == NULL) {
			crm_err("memory allocation failed in "
			       "decode_hash_value()\n");
			return FALSE;
		}
		crm_info("Decoded value: (%s:%d)", *subsys,
			 (int)strlen(*subsys));
		return TRUE;
		
	} else if (char_value != NULL) {
		if (decodeNVpair(char_value, '_', node, subsys)) {
			return TRUE;
		} else {
			*node = NULL;
			*subsys = NULL;
			return FALSE;
		}
	}
	return FALSE;
}


char *
crm_itoa(int an_int)
{
	int len = 32;
	char *buffer = NULL;
	
	crm_malloc(buffer, sizeof(char)*(len+1));
	if(buffer != NULL) {
		snprintf(buffer, len, "%d", an_int);
	}
	
	return buffer;
}

unsigned int crm_log_level = LOG_INFO;
extern int LogToLoggingDaemon(int priority, const char * buf, int bstrlen, gboolean use_pri_str);

gboolean
crm_log_init(const char *entity) 
{
	const char *test = "Testing log daemon connection";
	/* Redirect messages from glib functions to our handler */
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_ERROR      | G_LOG_LEVEL_CRITICAL
			  | G_LOG_LEVEL_WARNING  | G_LOG_LEVEL_MESSAGE
			  | G_LOG_LEVEL_INFO     | G_LOG_LEVEL_DEBUG
			  | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,
			  cl_glib_msg_handler, NULL);

	/* and for good measure... */
	g_log_set_always_fatal((GLogLevelFlags)0);    
	
	cl_log_set_entity(entity);
	cl_log_set_facility(LOG_LOCAL7);

#if 1
	cl_log_send_to_logging_daemon(FALSE);
	if(HA_FAIL == LogToLoggingDaemon(LOG_INFO, test, strlen(test), TRUE)) {
		crm_warn("Not using log daemon");

	} else {
		cl_log_send_to_logging_daemon(TRUE);
		crm_info("Enabled log daemon");
	}
#endif

	CL_SIGNAL(DEBUG_INC, alter_debug);
	CL_SIGNAL(DEBUG_DEC, alter_debug);

	return TRUE;
}

/* returns the old value */
unsigned int
set_crm_log_level(unsigned int level)
{
	unsigned int old = crm_log_level;

	while(crm_log_level < level) {
		alter_debug(DEBUG_INC);
	}
	while(crm_log_level > level) {
		alter_debug(DEBUG_DEC);
	}
	
	return old;
}

unsigned int
get_crm_log_level(void)
{
	return crm_log_level;
}

void
crm_log_message_adv(int level, const char *alt_debugfile, const HA_Message *msg)
{
	if(crm_log_level >= level) {
		const char *cur_debugfile = NULL;
		if(alt_debugfile) {
			cur_debugfile = cl_log_get_debugfile();
			cl_log_set_debugfile(alt_debugfile);
			do_crm_log(level, NULL, NULL, "#========= message start ==========#");
		}
		if(level > LOG_DEBUG) {
			cl_log_message(LOG_DEBUG, msg);
		} else {
			cl_log_message(level, msg);
		}
		if(cur_debugfile) {
			cl_log_set_debugfile(cur_debugfile);
		}
	}
}


void
do_crm_log(int log_level, const char *function,
	   const char *alt_debugfile, const char *fmt, ...)
{
	int log_as = log_level;
	gboolean do_log = FALSE;
	if(log_level < LOG_INFO) {
		do_log = TRUE;

	} else if(log_level <= crm_log_level) {
		do_log = TRUE;
		if(log_level > LOG_INFO) {
			log_as = LOG_DEBUG;
		}
	}

	if(do_log) {
		va_list ap;
		char	*buf = NULL;
		int	nbytes;
		
		va_start(ap, fmt);
		nbytes=vasprintf(&buf, fmt, ap);
		va_end(ap);

		log_level -= LOG_DEBUG;
		if(log_level > 0) {
			if(function == NULL) {
				cl_log(log_as, "[%d] %s", log_level, buf);
				
			} else {
				cl_log(log_as, "%s [%d]: %s",
				       function, log_level, buf);
			}

		} else {
			if(function == NULL) {
				cl_log(log_as, "%s", buf);
				
			} else {
				cl_log(log_as, "%s: %s", function, buf);
			}
		}
		
		if(nbytes > MAXLINE) {
			cl_log(LOG_WARNING, "Log from %s() was truncated",
			       crm_str(function));
		}
		free(buf);
	}
}

int
compare_version(const char *version1, const char *version2)
{
	int lpc = 0;
	char *step1 = NULL, *step2 = NULL;
	char *rest1 = NULL, *rest2 = NULL;

	if(version1 != NULL) {
		rest1 = crm_strdup(version1);
	} else {
		version1 = "<null>";
	}
	if(version2 != NULL) {
		rest2 = crm_strdup(version2);
	} else {
		version2 = "<null>";
	}
	
	while(1) {
		int cmp = 0;
		int step1_i = 0;
		int step2_i = 0;
		char *tmp1 = NULL, *tmp2 = NULL;
		
		decodeNVpair(rest1, '.', &step1, &tmp1);
		decodeNVpair(rest2, '.', &step2, &tmp2);

		if(step1 != NULL) {
			step1_i = atoi(step1);
		}
		if(step2 != NULL) {
			step2_i = atoi(step2);
		}

		if(step1_i < step2_i){
			cmp = -1;
		} else if (step1_i > step2_i){
			cmp = 1;
		}

		crm_trace("compare[%d (%d)]: %d(%s)  %d(%s)",
			  lpc++, cmp,
			  step1_i, crm_str(step1),
			  step2_i, crm_str(step2));

		crm_free(rest1);
		crm_free(rest2);

		rest1 = tmp1;
		rest2 = tmp2;

		if(step1 == NULL && step2 == NULL) {
			break;
		}

		crm_free(step1);
		crm_free(step2);
		
		if(cmp < 0) {
			crm_verbose("%s < %s", version1, version2);
			return -1;
			
		} else if(cmp > 0) {
			crm_verbose("%s > %s", version1, version2);
			return 1;
		}
	}
	crm_verbose("%s == %s", version1, version2);
	return 0;
}

gboolean do_stderr = FALSE;

void
alter_debug(int nsig) 
{
	CL_SIGNAL(DEBUG_INC, alter_debug);
	CL_SIGNAL(DEBUG_DEC, alter_debug);
	
	switch(nsig) {
		case DEBUG_INC:
			if(do_stderr == FALSE && crm_log_level == LOG_INFO) {
				do_stderr = TRUE;
				cl_log_enable_stderr(do_stderr);
				break;
			}

			crm_log_level++;
			fprintf(stderr,
				"Upped log level to %d\n", crm_log_level);
			cl_log(LOG_INFO,
			       "Upped log level to %d\n", crm_log_level);
			break;

		case DEBUG_DEC:
			if(do_stderr && crm_log_level == LOG_INFO) {
				do_stderr = FALSE;
				cl_log_enable_stderr(do_stderr);
				break;
			}

			crm_log_level--;
			fprintf(stderr,
				"Reduced log level to %d\n", crm_log_level);
			cl_log(LOG_INFO,
			       "Reduced log level to %d\n", crm_log_level);
			break;	

		default:
			fprintf(stderr, "Unknown signal %d\n", nsig);
			cl_log(LOG_ERR, "Unknown signal %d\n", nsig);
			break;	
	}
}


void g_hash_destroy_str(gpointer data)
{
	crm_free(data);
}

gboolean
safe_str_eq(const char *a, const char *b) 
{
	if(a == b) {
		return TRUE;		
	} else if(a == NULL || b == NULL) {
		return FALSE;
	} else if(strcmp(a, b) == 0) {
		return TRUE;
	}
	return FALSE;
}

gboolean
safe_str_neq(const char *a, const char *b)
{
	if(a == b) {
		return FALSE;

	} else if(a==NULL || b==NULL) {
		return TRUE;

	} else if(strcmp(a, b) == 0) {
		return FALSE;
	}
	return TRUE;
}

char *
crm_strdup(const char *a)
{
	char *ret = NULL;
	CRM_ASSERT(a != NULL);
	if(a != NULL) {
		ret = cl_strdup(a);
	} else {
		crm_warn("Cannot dup NULL string");
	}
	return ret;
} 

void
set_uuid(ll_cluster_t *hb,crm_data_t *node,const char *attr,const char *uname) 
{
	char *uuid_calc = NULL;
	
	crm_malloc(uuid_calc, sizeof(char)*50);

	if(uuid_calc != NULL) {
		uuid_t uuid_raw;
		if(hb->llc_ops->get_uuid_by_name(
			   hb, uname, uuid_raw) == HA_FAIL) {
			crm_err("Could not calculate UUID for %s", uname);
			crm_free(uuid_calc);
			uuid_calc = crm_strdup(uname);
			
		} else {
			uuid_unparse(uuid_raw, uuid_calc);
		}
		set_xml_property_copy(node, attr, uuid_calc);
	}
	
	crm_free(uuid_calc);
}/*memory leak*/ /* BEAM BUG - this is not a memory leak */

