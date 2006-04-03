/* $Id: atest.c,v 1.8 2006/04/03 10:03:06 andrew Exp $ */
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

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <apphb.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>
#include <clplumbing/coredumps.h>

#include <crm/crm.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#include <crmd.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crm/cib.h>

#include <crm/dmalloc_wrapper.h>

const char* crm_system_name = "core";

gboolean process_atest_message(
	HA_Message *msg, crm_data_t *xml_data, IPC_Channel *sender);


GMainLoop*  mainloop = NULL;

#define OPTARGS	"V?f:"
#include <bzlib.h>
int
main(int argc, char ** argv)
{
#if 0

	int start = 0, length = 0, read_len = 0;
	char *buffer = NULL;
	int rc = 0;
	FILE *file_strm = NULL;
	const char *my_msg = "my first message";
	char *compressed = NULL;
	size_t compressed_len = 100;

	char *decomp = NULL;
	size_t decomp_len = 1;
	size_t alloced_decomp_len = decomp_len;
	
	cl_log_enable_stderr(1);

	crm_malloc0(compressed, 100);
	
	cl_compress(compressed, &compressed_len, my_msg, strlen(my_msg));
	crm_err("Original: len: %zd, str: %s",
		strlen(my_msg), my_msg);
	
	crm_err("Compressed: len: %zd, str: %s",
		compressed_len, compressed);

	file_strm = fopen("foo.bz2", "w");
	rc = fprintf(file_strm, "%s", compressed);
	if(rc < 0) {
		cl_perror("Cannot write output to foo.bz2");
	}
	fflush(file_strm);
	fclose(file_strm);
	
	file_strm = fopen("foo.bz2", "r");
	start  = ftell(file_strm);
	fseek(file_strm, 0L, SEEK_END);
	length = ftell(file_strm);
	fseek(file_strm, 0L, start);
	
	CRM_ASSERT(start == ftell(file_strm));

	crm_err("Reading %d bytes from file", length);
	crm_malloc0(buffer, sizeof(char) * (length+1));
	read_len = fread(buffer, sizeof(char), length, file_strm);
	if(read_len != length) {
		crm_err("Calculated and read bytes differ: %d vs. %d",
			length, read_len);
		crm_free(buffer);
		buffer = NULL;
		
	} else  if(length <= 0) {
		crm_info("foo.bz2 was not valid");
		crm_free(buffer);
		buffer = NULL;
	}

	while(alloced_decomp_len <= decomp_len) {
		crm_err("Trying with buffer size: %zd", alloced_decomp_len);
		if(decomp != NULL) {
			crm_err("Found: %s", decomp);
			crm_free(decomp);
		}

		decomp_len = 2*decomp_len;
		crm_malloc0(decomp, (decomp_len+1)*sizeof(char));
		alloced_decomp_len = decomp_len;
		
		cl_decompress(decomp, &decomp_len, buffer, length);
/* 		cl_decompress(decomp, &decomp_len, compressed, compressed_len); */
	}
	
	crm_err("Decompressed: len: %zd, str: %s", decomp_len, decomp);
	
	return 0;
#else
	int rc = 0;
	FILE *file_strm = NULL;
	BZFILE *my_file = NULL;
	char *my_msg = strdup("my first message");
	unsigned int in = 0, out = 0;
	char *decomp = NULL;
	size_t decomp_len = 1;
	size_t alloced_decomp_len = decomp_len;
	
	cl_log_enable_stderr(1);
	file_strm = fopen("foo.bz2", "w");
	my_file = BZ2_bzWriteOpen(&rc, file_strm, 1, 0, 0);
	if(rc != BZ_OK) {
		crm_err("Failed: open (%d)", rc);
		return 0;
	}
	BZ2_bzWrite(&rc, my_file, my_msg, strlen(my_msg));
	if(rc != BZ_OK) {
		crm_err("Failed: write (%d)", rc);
		return 0;
	}
	BZ2_bzWriteClose(&rc, my_file, 0, &in, &out);
	crm_err("In: %d, out: %d", in, out);
	fclose(file_strm);
	my_file = NULL;
	file_strm = NULL;
	
	while(alloced_decomp_len <= decomp_len) {
		crm_err("Trying with buffer size: %zd", alloced_decomp_len);
		if(decomp != NULL) {
			crm_err("Found: %s", decomp);
			crm_free(decomp);
		}
		if(my_file != NULL) {
			crm_err("Closing...");
			BZ2_bzReadClose(&rc, my_file);
			fclose(file_strm);
		}
		file_strm = fopen("foo.bz2", "r");
		my_file = BZ2_bzReadOpen(&rc, file_strm, 0, 0, NULL, 0);
		if(rc != BZ_OK) {
			crm_err("Failed: read open (%d)", rc);
		}

		decomp_len = 2*decomp_len;
		crm_malloc0(decomp, (decomp_len+1)*sizeof(char));
		alloced_decomp_len = decomp_len;
		
		decomp_len = BZ2_bzRead(&rc, my_file, decomp, decomp_len);
		if(rc != BZ_OK) {
			crm_err("Failed: read (%d)", rc);
		}
	}
	
	crm_err("Decompressed: len: %zd, str: %s", decomp_len, decomp);
	return 0;
#endif
}

