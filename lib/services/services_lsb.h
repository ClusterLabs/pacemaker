/*
 * Copyright 2010-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef SERVICES_LSB__H
#  define SERVICES_LSB__H

G_GNUC_INTERNAL int services__get_lsb_metadata(const char *type, char **output);
G_GNUC_INTERNAL GList *services__list_lsb_agents(void);

#endif
