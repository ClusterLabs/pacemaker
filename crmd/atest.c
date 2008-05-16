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

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>

#define OPTARGS	"V?X:I:"

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

int
main(int argc, char ** argv)
{
    int flag;
    xmlNode *xml = NULL;
    const char *xml_file = NULL;
    const char *input_file = NULL;
    
    crm_log_init("atest", LOG_DEBUG, FALSE, TRUE, argc, argv);
    while (1) {
#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
	    /* Top-level Options */
	    {"help",        0, 0, '?'},
	    {"verbose",     0, 0, 'V'},			
	    
	    {"xml-file",    1, 0, 'X'},
	    {"save-input",  1, 0, 'I'},

	    {0, 0, 0, 0}
	};
#endif
    
#ifdef HAVE_GETOPT_H
	flag = getopt_long(argc, argv, OPTARGS,
			   long_options, &option_index);
#else
	flag = getopt(argc, argv, OPTARGS);
#endif
	if (flag == -1)
	    break;
	
	switch(flag) {
#ifdef HAVE_GETOPT_H
	    case 0:
		printf("option %s", long_options[option_index].name);
		if (optarg)
		    printf(" with arg %s", optarg);
		printf("\n");
		
		break;
#endif
	    case 'X':
		xml_file = optarg;
		break;
	    case 'I':
		input_file = optarg;
		break;
	    case '?':
		/* usage("ptest", 0); */
		break;
	    default:
		printf("?? getopt returned character code 0%o ??\n", flag);
		break;
	}
    }

    if(xml_file != NULL) {
	FILE *xml_strm = fopen(xml_file, "r");
	if(xml_strm == NULL) {
	    cl_perror("Could not open %s for reading", xml_file);
	    
	} else {
	    if(strstr(xml_file, ".bz2") != NULL) {
		xml = file2xml(xml_strm, TRUE);
		
	    } else {
		xml = file2xml(xml_strm, FALSE);
	    }
	    fclose(xml_strm);
	}
    }

    update_validation(&xml, TRUE, FALSE);
    crm_log_xml_info(xml, "fixed");
    
    return 0;
}

