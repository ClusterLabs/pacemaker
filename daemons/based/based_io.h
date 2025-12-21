/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_IO__H
#define BASED_IO__H

#include <libxml/tree.h>                // xmlNode

void based_io_init(void);
void based_enable_writes(int nsig);
xmlNode *based_read_cib(const char *dir);

#endif // BASED_IO__H
