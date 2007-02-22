/*
 * Copyright (C) 2001 Alan Robertson <alanr@unix.sh>
 * This software licensed under the GNU LGPL.
 *
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <lha_internal.h>
#include <stdlib.h>
#include <stdio.h>

/*
 *	Small replacement function for setenv()
 */
int
setenv(const char *name, const char * value, int why)
{
	int rc = -1;

	if ( name && value ) {
		char * envp = NULL;
		envp = malloc(strlen(name)+strlen(value)+2);
		if (envp) {
			/*
			 * Unfortunately, the putenv API guarantees memory leaks when
			 * changing environment variables repeatedly...   :-(
			 */

			sprintf(envp, "%s=%s", name, value);

			/* Cannot free envp (!) */
			rc = putenv(envp);
		}
	
	}
	return(rc);
}
