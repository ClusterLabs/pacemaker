/* $Id: utils.c,v 1.35 2006/03/17 17:59:32 andrew Exp $ */
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

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>


#include <heartbeat.h>
#include <ha_msg.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/cl_syslog.h>
#include <clplumbing/cl_misc.h>
#include <clplumbing/coredumps.h>

#include <time.h> 

#include <clplumbing/Gmain_timeout.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/dmalloc_wrapper.h>

#ifndef MAXLINE
#    define MAXLINE 512
#endif

static uint ref_counter = 0;
gboolean crm_assert_failed = FALSE;
unsigned int crm_log_level = LOG_INFO;

void crm_set_env_options(void);

char *
generateReference(const char *custom1, const char *custom2)
{

	const char *local_cust1 = custom1;
	const char *local_cust2 = custom2;
	int reference_len = 4;
	char *since_epoch = NULL;

	reference_len += 20; /* too big */
	reference_len += 40; /* too big */
	
	if(local_cust1 == NULL) { local_cust1 = "_empty_"; }
	reference_len += strlen(local_cust1);
	
	if(local_cust2 == NULL) { local_cust2 = "_empty_"; }
	reference_len += strlen(local_cust2);
	
	crm_malloc0(since_epoch, reference_len*(sizeof(char)));

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

	CRM_ASSERT(name != NULL && value != NULL);
	*name = NULL;
	*value = NULL;

	crm_debug_4("Attempting to decode: [%s]", srcstring);
	if (srcstring != NULL) {
		len = strlen(srcstring);
		while(lpc <= len) {
			if (srcstring[lpc] == separator) {
				crm_malloc0(*name, sizeof(char)*lpc+1);
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

					crm_malloc0(*value, sizeof(char)*len+1);
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

	if(*name != NULL) {
		crm_free(*name);
	}
	*name = NULL;
	*value = NULL;
    
	return FALSE;
}

char *
crm_concat(const char *prefix, const char *suffix, char join) 
{
	int len = 0;
	char *new_str = NULL;
	CRM_ASSERT(prefix != NULL);
	CRM_ASSERT(suffix != NULL);
	len = strlen(prefix) + strlen(suffix) + 2;

	crm_malloc0(new_str, sizeof(char)*(len));
	sprintf(new_str, "%s%c%s", prefix, join, suffix);
	new_str[len-1] = 0;
	return new_str;
}


char *
generate_hash_key(const char *crm_msg_reference, const char *sys)
{
	char *hash_key = crm_concat(sys?sys:"none", crm_msg_reference, '_');
	crm_debug_3("created hash key: (%s)", hash_key);
	return hash_key;
}

char *
generate_hash_value(const char *src_node, const char *src_subsys)
{
	char *hash_value = NULL;
	
	if (src_node == NULL || src_subsys == NULL) {
		return NULL;
	}
    
	if (strcmp(CRM_SYSTEM_DC, src_subsys) == 0) {
		hash_value = crm_strdup(src_subsys);
		if (!hash_value) {
			crm_err("memory allocation failed in "
			       "generate_hash_value()");
		}
		return hash_value;
	}

	hash_value = crm_concat(src_node, src_subsys, '_');
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
			       "decode_hash_value()");
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
	
	crm_malloc0(buffer, sizeof(char)*(len+1));
	if(buffer != NULL) {
		snprintf(buffer, len, "%d", an_int);
	}
	
	return buffer;
}

extern int LogToLoggingDaemon(int priority, const char * buf, int bstrlen, gboolean use_pri_str);

gboolean
crm_log_init(const char *entity) 
{
/* 	const char *test = "Testing log daemon connection"; */
	/* Redirect messages from glib functions to our handler */
/*  	cl_malloc_forced_for_glib(); */
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_ERROR      | G_LOG_LEVEL_CRITICAL
			  | G_LOG_LEVEL_WARNING  | G_LOG_LEVEL_MESSAGE
			  | G_LOG_LEVEL_INFO     | G_LOG_LEVEL_DEBUG
			  | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,
			  cl_glib_msg_handler, NULL);

	/* and for good measure... - this enum is a bit field (!) */
	g_log_set_always_fatal((GLogLevelFlags)0); /*value out of range*/
	
	cl_log_set_entity(entity);
	cl_log_set_facility(LOG_LOCAL7);

	cl_set_corerootdir(HA_COREDIR);	    
	cl_cdtocoredir();
	
	crm_set_env_options();

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
crm_log_message_adv(int level, const char *prefix, const HA_Message *msg)
{
	if((int)crm_log_level >= level) {
		do_crm_log(level, NULL, NULL, "#========= %s message start ==========#", prefix?prefix:"");
		if(level > LOG_DEBUG) {
			cl_log_message(LOG_DEBUG, msg);
		} else {
			cl_log_message(level, msg);
		}
	}
}


void
do_crm_log(int log_level, const char *file, const char *function,
	   const char *fmt, ...)
{
	int log_as = log_level;
	gboolean do_log = FALSE;
	if(log_level <= (int)crm_log_level) {
		do_log = TRUE;
		if(log_level > LOG_INFO) {
			log_as = LOG_DEBUG;
		}
	}

	if(do_log) {
		va_list ap;
		int	nbytes;
		char    buf[MAXLINE];
		
		va_start(ap, fmt);
		nbytes=vsnprintf(buf, MAXLINE, fmt, ap);
		va_end(ap);

		log_level -= LOG_INFO;
		if(log_level > 1) {
			if(file == NULL && function == NULL) {
				cl_log(log_as, "[%d] %s", log_level, buf);
				
			} else {
				cl_log(log_as, "mask(%s%s%s [%d]): %s",
				       file?file:"",
				       (file !=NULL && function !=NULL)?":":"",
				       function?function:"", log_level, buf);
			}

		} else {
			if(file == NULL && function == NULL) {
				cl_log(log_as, "%s", buf);
				
			} else {
				cl_log(log_as, "mask(%s%s%s): %s",
				       file?file:"",
				       (file !=NULL && function !=NULL)?":":"",
				       function?function:"", buf);
			}
		}

		if(nbytes > MAXLINE) {
			cl_log(LOG_WARNING, "Log from %s() was truncated",
			       crm_str(function));
		}
	}
}

int
compare_version(const char *version1, const char *version2)
{
	int lpc = 0;
	char *step1 = NULL, *step2 = NULL;
	char *rest1 = NULL, *rest2 = NULL;

	if(version1 == NULL && version2 == NULL) {
		return 0;
	} else if(version1 == NULL) {
		return -1;
	} else if(version2 == NULL) {
		return 1;
	}
	
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
			step1_i = crm_parse_int(step1, NULL);
		}
		if(step2 != NULL) {
			step2_i = crm_parse_int(step2, NULL);
		}

		if(step1_i < step2_i){
			cmp = -1;
		} else if (step1_i > step2_i){
			cmp = 1;
		}

		crm_debug_4("compare[%d (%d)]: %d(%s)  %d(%s)",
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
			crm_debug_3("%s < %s", version1, version2);
			return -1;
			
		} else if(cmp > 0) {
			crm_debug_3("%s > %s", version1, version2);
			return 1;
		}
	}
	crm_debug_3("%s == %s", version1, version2);
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
			crm_log_level++;
			break;

		case DEBUG_DEC:
			crm_log_level--;
			break;	

		default:
			fprintf(stderr, "Unknown signal %d\n", nsig);
			cl_log(LOG_ERR, "Unknown signal %d", nsig);
			break;	
	}
}


void g_hash_destroy_str(gpointer data)
{
	crm_free(data);
}

int
crm_int_helper(const char *text, char **end_text)
{
	int atoi_result = -1;
	char *local_end_text = NULL;

	errno = 0;
	
	if(text != NULL) {
		if(end_text != NULL) {
			atoi_result = (int)strtol(text, end_text, 10);
		} else {
			atoi_result = (int)strtol(text, &local_end_text, 10);
		}
		
/* 		CRM_DEV_ASSERT(errno != EINVAL); */
		if(errno == EINVAL) {
			crm_err("Conversion of %s failed", text);
			atoi_result = -1;
			
		} else {
			if(errno == ERANGE) {
				crm_err("Conversion of %s was clipped", text);
			}
			if(end_text == NULL && local_end_text[0] != '\0') {
				crm_err("Characters left over after parsing "
					"\"%s\": \"%s\"", text, local_end_text);
			}
				
		}
	}
	return atoi_result;
}

int
crm_parse_int(const char *text, const char *default_text)
{
	int atoi_result = -1;
	if(text != NULL) {
		atoi_result = crm_int_helper(text, NULL);
		if(errno == 0) {
			return atoi_result;
		}
	}
	
	if(default_text != NULL) {
		atoi_result = crm_int_helper(default_text, NULL);
		if(errno == 0) {
			return atoi_result;
		}

	} else {
		crm_err("No default conversion value supplied");
	}

	return -1;
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
	CRM_DEV_ASSERT(a != NULL);
	if(a != NULL) {
		ret = cl_strdup(a);
	} else {
		crm_warn("Cannot dup NULL string");
	}
	return ret;
} 

static GHashTable *crm_uuid_cache = NULL;
static GHashTable *crm_uname_cache = NULL;

void
unget_uuid(const char *uname)
{
	if(crm_uuid_cache == NULL) {
		return;
	}
	g_hash_table_remove(crm_uuid_cache, uname);
}
const char *
get_uuid(ll_cluster_t *hb, const char *uname) 
{
	cl_uuid_t uuid_raw;
	char *uuid_calc = NULL;
	const char *unknown = "00000000-0000-0000-0000-000000000000";

	if(crm_uuid_cache == NULL) {
		crm_uuid_cache = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
	}
	
	CRM_DEV_ASSERT(uname != NULL);

	/* avoid blocking calls where possible */
	uuid_calc = g_hash_table_lookup(crm_uuid_cache, uname);
	if(uuid_calc != NULL) {
		return uuid_calc;
	}
	
	
	if(hb->llc_ops->get_uuid_by_name(hb, uname, &uuid_raw) == HA_FAIL) {
		crm_err("get_uuid_by_name() call failed for host %s", uname);
		crm_free(uuid_calc);
		return NULL;
		
	} 

	crm_malloc0(uuid_calc, sizeof(char)*50);
	
	if(uuid_calc == NULL) {
		return NULL;
	}

	cl_uuid_unparse(&uuid_raw, uuid_calc);

	if(safe_str_eq(uuid_calc, unknown)) {
		crm_warn("Could not calculate UUID for %s", uname);
		crm_free(uuid_calc);
		return NULL;
	}
	
	g_hash_table_insert(crm_uuid_cache, crm_strdup(uname), uuid_calc);
	uuid_calc = g_hash_table_lookup(crm_uuid_cache, uname);

	return uuid_calc;
}

const char *
get_uname(ll_cluster_t *hb, const char *uuid) 
{
	char *uname = NULL;

	if(crm_uuid_cache == NULL) {
		crm_uname_cache = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
	}
	
	CRM_DEV_ASSERT(uuid != NULL);

	/* avoid blocking calls where possible */
	uname = g_hash_table_lookup(crm_uname_cache, uuid);
	if(uname != NULL) {
		return uname;
	}
	
	if(uuid != NULL) {
		cl_uuid_t uuid_raw;
		char *uuid_copy = crm_strdup(uuid);
		cl_uuid_parse(uuid_copy, &uuid_raw);
		
		if(hb->llc_ops->get_name_by_uuid(
			   hb, &uuid_raw, uname, 256) == HA_FAIL) {
			crm_err("Could not calculate UUID for %s", uname);
			uname = NULL;
			crm_free(uuid_copy);
			
		} else {
			g_hash_table_insert(
				crm_uuid_cache,
				uuid_copy, crm_strdup(uname));
			uname = g_hash_table_lookup(crm_uname_cache, uuid);
		}
		return uname;
	}
	return NULL;
}

void
set_uuid(ll_cluster_t *hb,crm_data_t *node,const char *attr,const char *uname) 
{
	const char *uuid_calc = get_uuid(hb, uname);
	crm_xml_add(node, attr, uuid_calc);
	return;
}


void
crm_set_ha_options(ll_cluster_t *hb_cluster) 
{
#if 0
	int facility;
	char *param_val = NULL;
	const char *param_name = NULL;

	if(hb_cluster == NULL) {
		crm_set_env_options();
		return;
	}
	
	/* change the logging facility to the one used by heartbeat daemon */
	crm_debug("Switching to Heartbeat logger");
	if (( facility =
	      hb_cluster->llc_ops->get_logfacility(hb_cluster)) > 0) {
		cl_log_set_facility(facility);
 	}	
	crm_debug_2("Facility: %d", facility);

	param_name = KEY_LOGFILE;
	param_val = hb_cluster->llc_ops->get_parameter(hb_cluster, param_name);
	crm_debug_3("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		cl_log_set_logfile(param_val);
		cl_free(param_val);
		param_val = NULL;
	}
	
	param_name = KEY_DBGFILE;
	param_val = hb_cluster->llc_ops->get_parameter(hb_cluster, param_name);
	crm_debug_3("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		cl_log_set_debugfile(param_val);
		cl_free(param_val);
		param_val = NULL;
	}
	
	param_name = KEY_DEBUGLEVEL;
	param_val = hb_cluster->llc_ops->get_parameter(hb_cluster, param_name);
	crm_debug_3("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		int debug_level = crm_parse_int(param_val, NULL);
		if(debug_level > 0 && (debug_level+LOG_INFO) > (int)crm_log_level) {
			set_crm_log_level(LOG_INFO + debug_level);
		}
		cl_free(param_val);
		param_val = NULL;
	}

	param_name = KEY_LOGDAEMON;
	param_val = hb_cluster->llc_ops->get_parameter(hb_cluster, param_name);
	crm_debug_3("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		int uselogd;
		cl_str_to_boolean(param_val, &uselogd);
		cl_log_set_uselogd(uselogd);
		if(cl_log_get_uselogd()) {
			cl_set_logging_wqueue_maxlen(500);
		}
		cl_free(param_val);
		param_val = NULL;
	}

	param_name = KEY_CONNINTVAL;
	param_val = hb_cluster->llc_ops->get_parameter(hb_cluster, param_name);
	crm_debug_3("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		int logdtime;
		logdtime = crm_get_msec(param_val);
		cl_log_set_logdtime(logdtime);
		cl_free(param_val);
		param_val = NULL;
	}
#endif
}


#define ENV_PREFIX "HA_"
void
crm_set_env_options(void) 
{
	char *param_val = NULL;
	const char *param_name = NULL;

	/* apparently we're not allowed to free the result of getenv */
	
	param_name = ENV_PREFIX "" KEY_DEBUGLEVEL;
	param_val = getenv(param_name);
	if(param_val != NULL) {
		int debug_level = crm_parse_int(param_val, NULL);
		if(debug_level > 0 && (debug_level+LOG_INFO) > (int)crm_log_level) {
			set_crm_log_level(LOG_INFO + debug_level);
		}
		crm_debug("%s = %s", param_name, param_val);
		param_val = NULL;
	}

	param_name = ENV_PREFIX "" KEY_FACILITY;
	param_val = getenv(param_name);
	crm_debug("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		int facility = cl_syslogfac_str2int(param_val);
		if(facility > 0) {
			cl_log_set_facility(facility);
		}
		param_val = NULL;
	}

	param_name = ENV_PREFIX "" KEY_LOGFILE;
	param_val = getenv(param_name);
	crm_debug("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		if(safe_str_eq("/dev/null", param_val)) {
			param_val = NULL;
		}
		cl_log_set_logfile(param_val);
		param_val = NULL;
	}
	
	param_name = ENV_PREFIX "" KEY_DBGFILE;
	param_val = getenv(param_name);
	crm_debug("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		if(safe_str_eq("/dev/null", param_val)) {
			param_val = NULL;
		}
		cl_log_set_debugfile(param_val);
		param_val = NULL;
	}
	
	param_name = ENV_PREFIX "" KEY_LOGDAEMON;
	param_val = getenv(param_name);
	crm_debug("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		int uselogd;
		cl_str_to_boolean(param_val, &uselogd);
		cl_log_set_uselogd(uselogd);
		if(uselogd) {
			cl_set_logging_wqueue_maxlen(500);
			cl_log_set_logd_channel_source(NULL, NULL);
		}
		param_val = NULL;
	}

	param_name = ENV_PREFIX "" KEY_CONNINTVAL;
	param_val = getenv(param_name);
	crm_debug("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		int logdtime;
		logdtime = crm_get_msec(param_val);
		cl_log_set_logdtime(logdtime);
		param_val = NULL;
	}
	
	inherit_compress();
}

gboolean
crm_is_true(const char * s)
{
	gboolean ret = FALSE;
	if(s != NULL) {
		cl_str_to_boolean(s, &ret);
	}
	return ret;
}

int
crm_str_to_boolean(const char * s, int * ret)
{
	if(s == NULL) {
		return -1;

	} else if (strcasecmp(s, "true") == 0
		   ||	strcasecmp(s, "on") == 0
		   ||	strcasecmp(s, "yes") == 0
		   ||	strcasecmp(s, "y") == 0
		   ||	strcasecmp(s, "1") == 0){
		*ret = TRUE;
		return 1;

	} else if (strcasecmp(s, "false") == 0
		   ||	strcasecmp(s, "off") == 0
		   ||	strcasecmp(s, "no") == 0
		   ||	strcasecmp(s, "n") == 0
		   ||	strcasecmp(s, "0") == 0){
		*ret = FALSE;
		return 1;
	}
	return -1;
}

#ifndef NUMCHARS
#    define	NUMCHARS	"0123456789."
#endif

#ifndef WHITESPACE
#    define	WHITESPACE	" \t\n\r\f"
#endif

long
crm_get_msec(const char * input)
{
	const char *	cp = input;
	const char *	units;
	long		multiplier = 1000;
	long		divisor = 1;
	long		ret = -1;
	double		dret;

	if(input == NULL) {
		return 0;
	}
	
	cp += strspn(cp, WHITESPACE);
	units = cp + strspn(cp, NUMCHARS);
	units += strspn(units, WHITESPACE);

	if (strchr(NUMCHARS, *cp) == NULL) {
		return ret;
	}

	if (strncasecmp(units, "ms", 2) == 0
	||	strncasecmp(units, "msec", 4) == 0) {
		multiplier = 1;
		divisor = 1;
	}else if (strncasecmp(units, "us", 2) == 0
	||	strncasecmp(units, "usec", 4) == 0) {
		multiplier = 1;
		divisor = 1000;
	}else if (strncasecmp(units, "s", 1) == 0
	||	strncasecmp(units, "sec", 3) == 0) {
		multiplier = 1000;
		divisor = 1;	
	}else if (strncasecmp(units, "m", 1) == 0
	||	strncasecmp(units, "min", 3) == 0) {
		multiplier = 60*1000;
		divisor = 1;	
	}else if (*units != EOS && *units != '\n'
	&&	*units != '\r') {
		return ret;
	}
	dret = atof(cp);
	dret *= (double)multiplier;
	dret /= (double)divisor;
	dret += 0.5;
	ret = (long)dret;
	return(ret);
}

gboolean
ccm_have_quorum(oc_ed_t event)
{
	if(event==OC_EV_MS_NEW_MEMBERSHIP) {
		return TRUE;
	}
	return FALSE;
}


const char *
ccm_event_name(oc_ed_t event)
{

	if(event==OC_EV_MS_NEW_MEMBERSHIP) {
		return "NEW MEMBERSHIP";

	} else if(event==OC_EV_MS_NOT_PRIMARY) {
		return "NOT PRIMARY";

	} else if(event==OC_EV_MS_PRIMARY_RESTORED) {
		return "PRIMARY RESTORED";
		
	} else if(event==OC_EV_MS_EVICTED) {
		return "EVICTED";

	} else if(event==OC_EV_MS_INVALID) {
		return "INVALID";
	}

	return "NO QUORUM MEMBERSHIP";
	
}

const char *
op_status2text(op_status_t status)
{
	switch(status) {
		case LRM_OP_PENDING:
			return "pending";
			break;
		case LRM_OP_DONE:
			return "complete";
			break;
		case LRM_OP_ERROR:
			return "Error";
			break;
		case LRM_OP_TIMEOUT:
			return "Timed Out";
			break;
		case LRM_OP_NOTSUPPORTED:
			return "NOT SUPPORTED";
			break;
		case LRM_OP_CANCELLED:
			return "Cancelled";
			break;
	}
	CRM_DEV_ASSERT(status >= LRM_OP_PENDING && status <= LRM_OP_CANCELLED);
	crm_err("Unknown status: %d", status);
	return "UNKNOWN!";
}

char *
generate_op_key(const char *rsc_id, const char *op_type, int interval)
{
	int len = 35;
	char *op_id = NULL;

	CRM_DEV_ASSERT(rsc_id  != NULL); if(crm_assert_failed) { return NULL; }
	CRM_DEV_ASSERT(op_type != NULL); if(crm_assert_failed) { return NULL; }
	
	len += strlen(op_type);
	len += strlen(rsc_id);
	crm_malloc0(op_id, sizeof(char)*len);
	if(op_id != NULL) {
		sprintf(op_id, "%s_%s_%d", rsc_id, op_type, interval);
	}
	return op_id;
}

char *
generate_notify_key(const char *rsc_id, const char *notify_type, const char *op_type)
{
	int len = 12;
	char *op_id = NULL;

	CRM_DEV_ASSERT(rsc_id  != NULL); if(crm_assert_failed) { return NULL; }
	CRM_DEV_ASSERT(op_type != NULL); if(crm_assert_failed) { return NULL; }
	CRM_DEV_ASSERT(notify_type != NULL); if(crm_assert_failed) { return NULL; }
	
	len += strlen(op_type);
	len += strlen(rsc_id);
	len += strlen(notify_type);
	crm_malloc0(op_id, sizeof(char)*len);
	if(op_id != NULL) {
		sprintf(op_id, "%s_%s_notify_%s_0", rsc_id, notify_type, op_type);
	}
	return op_id;
}

char *
generate_transition_magic_v202(const char *transition_key, int op_status)
{
	int len = 80;
	char *fail_state = NULL;

	CRM_DEV_ASSERT(transition_key != NULL);
	if(crm_assert_failed) { return NULL; }
	
	len += strlen(transition_key);
	
	crm_malloc0(fail_state, sizeof(char)*len);
	if(fail_state != NULL) {
		snprintf(fail_state, len, "%d:%s", op_status,transition_key);
	}
	return fail_state;
}

char *
generate_transition_magic(const char *transition_key, int op_status, int op_rc)
{
	int len = 80;
	char *fail_state = NULL;

	CRM_DEV_ASSERT(transition_key != NULL);
	if(crm_assert_failed) { return NULL; }
	
	len += strlen(transition_key);
	
	crm_malloc0(fail_state, sizeof(char)*len);
	if(fail_state != NULL) {
		snprintf(fail_state, len, "%d:%d;%s",
			 op_status, op_rc, transition_key);
	}
	return fail_state;
}

gboolean
decode_transition_magic(
	const char *magic, char **uuid, int *transition_id,
	int *op_status, int *op_rc)
{
	char *rc = NULL;
	char *key = NULL;
	char *magic2 = NULL;
	char *status = NULL;

	if(decodeNVpair(magic, ':', &status, &magic2) == FALSE) {
		crm_err("Couldn't find ':' in: %s", magic);
		return FALSE;
	}

	if(decodeNVpair(magic2, ';', &rc, &key) == FALSE) {
		crm_err("Couldn't find ';' in: %s", magic2);
		return FALSE;
	}

	
	CRM_DEV_ASSERT(decode_transition_key(key, uuid, transition_id));
	if(crm_assert_failed) {
		return FALSE;
	}
	
	*op_rc = crm_parse_int(rc, NULL);
	*op_status = crm_parse_int(status, NULL);

	crm_free(rc);
	crm_free(key);
	crm_free(magic2);
	crm_free(status);
	
	return TRUE;
}

char *
generate_transition_key(int transition_id, const char *node)
{
	int len = 40;
	char *fail_state = NULL;

	CRM_DEV_ASSERT(node != NULL); if(crm_assert_failed) { return NULL; }
	
	len += strlen(node);
	
	crm_malloc0(fail_state, sizeof(char)*len);
	if(fail_state != NULL) {
		snprintf(fail_state, len, "%d:%s", transition_id, node);
	}
	return fail_state;
}


gboolean
decode_transition_key(const char *key, char **uuid, int *transition_id)
{
	char *transition = NULL;
	
	if(decodeNVpair(key, ':', &transition, uuid) == FALSE) {
		crm_err("Couldn't find ':' in: %s", key);
		return FALSE;
	}
	
	*transition_id = crm_parse_int(transition, NULL);

	crm_free(transition);
	
	return TRUE;
}


gboolean
crm_mem_stats(volatile cl_mem_stats_t *mem_stats)
{
	volatile cl_mem_stats_t *active_stats = mem_stats;
	if(active_stats == NULL) {
		active_stats = cl_malloc_getstats();
	}
	CRM_DEV_ASSERT(active_stats != NULL);
#ifndef CRM_USE_MALLOC
	if(active_stats->numalloc > active_stats->numfree) {
		crm_warn("Potential memory leak detected:"
			" %lu alloc's vs. %lu free's (%lu)"
			" (%lu bytes not freed: req=%lu, alloc'd=%lu)",
			active_stats->numalloc, active_stats->numfree,
			active_stats->numalloc - active_stats->numfree,
			active_stats->nbytes_alloc, active_stats->nbytes_req,
			active_stats->mallocbytes);
		return TRUE;
		
	} else if(active_stats->numalloc < active_stats->numfree) {
		crm_debug("Process shrank: %lu alloc's vs. %lu free's (%lu)",
			  active_stats->numalloc, active_stats->numfree,
			  active_stats->numalloc - active_stats->numfree);
	}
#endif
	return FALSE;
}

void
crm_zero_mem_stats(volatile cl_mem_stats_t *stats)
{
	volatile cl_mem_stats_t *active_stats = NULL;
	if(stats != NULL) {
		cl_malloc_setstats(stats);
	}
	active_stats = cl_malloc_getstats();
	active_stats->numalloc = 0;
	active_stats->numfree = 0;
	active_stats->numrealloc = 0;
	active_stats->nbytes_req = 0;
	active_stats->nbytes_alloc = 0;
	active_stats->mallocbytes = 0;
	active_stats->arena = 0;
}


void
crm_abort(const char *file, const char *function, int line,
	  const char *assert_condition, gboolean do_fork)
{
	int pid = 0;

	if(do_fork) {
		pid=fork();
	}
	
	switch(pid) {
		case -1:
			crm_err("Cannot fork!");
			return;

		default:	/* Parent */
			crm_debug("Child %d forked to record assert failure", pid);
			return;

		case 0:		/* Child */
			break;
	}

	/* create a new process group to avoid
	 * being interupted by heartbeat
	 */
	setpgid(0, 0);
	do_crm_log(LOG_ERR, file, function,
 		   "Triggered %sfatal assert at %s:%d : %s",
 		   do_fork?"non-":"", file, line, assert_condition);

	abort();
}
