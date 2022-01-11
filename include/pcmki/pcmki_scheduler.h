/*
 * Copyright 2014-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_SCHEDULER__H
#  define PCMK__PCMKI_PCMKI_SCHEDULER__H

typedef struct rsc_ticket_s rsc_ticket_t;

#  include <glib.h>
#  include <crm/crm.h>
#  include <crm/common/iso8601.h>
#  include <crm/pengine/rules.h>
#  include <crm/pengine/common.h>
#  include <crm/pengine/status.h>

#  include <crm/pengine/complex.h>

enum pe_weights {
    pe_weights_none = 0x0,
    pe_weights_init = 0x1,
    pe_weights_forward = 0x4,
    pe_weights_positive = 0x8,
    pe_weights_rollback = 0x10,
};

typedef struct {
    const char *id;
    const char *node_attribute;
    pe_resource_t *dependent;   // The resource being colocated
    pe_resource_t *primary;     // The resource the dependent is colocated with

    int dependent_role; // Colocation applies only if dependent has this role
    int primary_role;   // Colocation applies only if primary has this role

    int score;
    bool influence; // Whether dependent influences active primary placement
} pcmk__colocation_t;

enum loss_ticket_policy_e {
    loss_ticket_stop,
    loss_ticket_demote,
    loss_ticket_fence,
    loss_ticket_freeze
};

struct rsc_ticket_s {
    const char *id;
    pe_resource_t *rsc_lh;
    pe_ticket_t *ticket;
    enum loss_ticket_policy_e loss_policy;

    int role_lh;
};

extern gboolean stage0(pe_working_set_t * data_set);
extern gboolean stage2(pe_working_set_t * data_set);
extern gboolean stage5(pe_working_set_t * data_set);
extern gboolean stage6(pe_working_set_t * data_set);

void pcmk__unpack_constraints(pe_working_set_t *data_set);

extern void add_maintenance_update(pe_working_set_t *data_set);
xmlNode *pcmk__schedule_actions(pe_working_set_t *data_set, xmlNode *xml_input,
                                crm_time_t *now);

extern const char *transition_idle_timeout;

/*!
 * \internal
 * \brief Check whether colocation's left-hand preferences should be considered
 *
 * \param[in] colocation  Colocation constraint
 * \param[in] rsc         Right-hand instance (normally this will be
 *                        colocation->primary, which NULL will be treated as,
 *                        but for clones or bundles with multiple instances
 *                        this can be a particular instance)
 *
 * \return true if colocation influence should be effective, otherwise false
 */
static inline bool
pcmk__colocation_has_influence(const pcmk__colocation_t *colocation,
                               const pe_resource_t *rsc)
{
    if (rsc == NULL) {
        rsc = colocation->primary;
    }

    /* The left hand of a colocation influences the right hand's location
     * if the influence option is true, or the right hand is not yet active.
     */
    return colocation->influence || (rsc->running_on == NULL);
}

#endif
