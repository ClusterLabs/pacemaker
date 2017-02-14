/*
 * Copyright (C) 2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK_ATTRD_COMMON__H
#  define PCMK_ATTRD_COMMON__H

void attrd_init_mainloop(void);
void attrd_run_mainloop(void);
gboolean attrd_mainloop_running(void);
void attrd_quit_mainloop(void);

gboolean attrd_shutting_down(void);
void attrd_shutdown(int nsig);
void attrd_init_ipc(qb_ipcs_service_t **ipcs,
                    qb_ipcs_msg_process_fn dispatch_fn);

gboolean attrd_value_needs_expansion(const char *value);
int attrd_expand_value(const char *value, const char *old_value);

#endif /* PCMK_ATTRD_COMMON__H */
