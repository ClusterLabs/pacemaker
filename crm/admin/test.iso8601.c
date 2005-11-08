/* $Id: test.iso8601.c,v 1.3 2005/11/08 17:02:43 davidlee Exp $ */
/* 
 * Copyright (C) 2005 Andrew Beekhof <andrew@beekhof.net>
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
#include <crm/common/iso8601.h>

#define OPTARGS	"V?d:p:D:WOL"

char command = 0;

int
main(int argc, char **argv)
{
	int argerr = 0;
	int flag;
	int print_options = 0;
	char *input_s = NULL;
	char *mutable_s = NULL;
	
	crm_log_init("iso8601");
	cl_log_set_facility(LOG_USER);
	cl_log_enable_stderr(TRUE);
	
	if(argc < 2) {
		argerr++;
	}

	while (1) {
		flag = getopt(argc, argv, OPTARGS);
		if (flag == -1)
			break;

		switch(flag) {
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case '?':
				break;
			case 'd':
			case 'p':
			case 'D':
				command = flag;
				input_s = crm_strdup(optarg);
				break;
			case 'W':
				print_options |= ha_date_weeks;
				break;
			case 'O':
				print_options |= ha_date_ordinal;
				break;
			case 'L':
				print_options |= ha_log_local;
				break;
		}
	}

	CRM_ASSERT(input_s != NULL);
	mutable_s = input_s;

	if(command == 'd') {
		ha_time_t *date_time = parse_date(&mutable_s);
		CRM_ASSERT(date_time != NULL);
		log_date(LOG_INFO, "parsed", date_time,
			 print_options|ha_log_date|ha_log_time);
		
	} else if(command == 'p') {
		ha_time_period_t *interval = parse_time_period(&mutable_s);
		CRM_ASSERT(interval != NULL);
		log_time_period(LOG_INFO, interval,
				print_options|ha_log_date|ha_log_time);
		
	} else if(command == 'D') {
		ha_time_t *duration = parse_time_duration(&mutable_s);
		CRM_ASSERT(duration != NULL);
		
	}
	return 0;
}
