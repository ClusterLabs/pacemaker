/*
 * Copyright 2013-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

void throttle_init(void);
void throttle_fini(void);
void controld_configure_throttle(GHashTable *options);

void throttle_update(xmlNode *xml);
int throttle_get_job_limit(const char *node);
int throttle_get_total_job_limit(int l);
