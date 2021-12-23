/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__PCMKI_PCMKI_SCHED_NOTIF__H
#  define PCMK__PCMKI_PCMKI_SCHED_NOTIF__H

#  include <crm/common/xml_internal.h>
#  include <crm/pengine/internal.h>

void pcmk__create_notification_keys(pe_resource_t *rsc, notify_data_t *n_data,
                                    pe_working_set_t *data_set);

void create_notifications(pe_resource_t *rsc, notify_data_t *n_data,
                          pe_working_set_t *data_set);

void free_notification_data(notify_data_t *n_data);

void create_secondary_notification(pe_action_t *action, pe_resource_t *rsc,
                                   pe_action_t *stonith_op,
                                   pe_working_set_t *data_set);

#endif /* PCMK__PCMKI_SCHED_NOTIF__H */
