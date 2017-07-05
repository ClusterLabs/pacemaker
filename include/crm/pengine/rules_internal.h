/*
 * Copyright (C) 2015-2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef RULES_INTERNAL_H
#define RULES_INTERNAL_H

#include <libxml/tree.h>

void pe_unpack_alerts(xmlNode *alerts);

#ifdef RHEL7_COMPAT
void pe_enable_legacy_alerts(const char *script, const char *target);
#endif

#endif
