/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PENGINE_UNPACK__H
#  define PENGINE_UNPACK__H

extern gboolean unpack_remote_nodes(xmlNode * xml_resources, pe_working_set_t * data_set);

extern gboolean unpack_resources(xmlNode * xml_resources, pe_working_set_t * data_set);

extern gboolean unpack_config(xmlNode * config, pe_working_set_t * data_set);

extern gboolean unpack_nodes(xmlNode * xml_nodes, pe_working_set_t * data_set);

extern gboolean unpack_tags(xmlNode * xml_tags, pe_working_set_t * data_set);

extern gboolean unpack_status(xmlNode * status, pe_working_set_t * data_set);

extern gint sort_op_by_callid(gconstpointer a, gconstpointer b);

extern gboolean unpack_lrm_resources(pe_node_t * node, xmlNode * lrm_state,
                                     pe_working_set_t * data_set);

// Some warnings we don't want to print every transition

enum pe_warn_once_e {
    pe_wo_blind         = 0x0001,
    pe_wo_restart_type  = 0x0002,
    pe_wo_role_after    = 0x0004,
    pe_wo_poweroff      = 0x0008,
    pe_wo_require_all   = 0x0010,
    pe_wo_order_score   = 0x0020,
    pe_wo_neg_threshold = 0x0040,
};

extern uint32_t pe_wo;

#define pe_warn_once(pe_wo_bit, fmt...) do {    \
        if (is_not_set(pe_wo, pe_wo_bit)) {     \
            if (pe_wo_bit == pe_wo_blind) {     \
                crm_warn(fmt);                  \
            } else {                            \
                pe_warn(fmt);                   \
            }                                   \
            set_bit(pe_wo, pe_wo_bit);          \
        }                                       \
    } while (0);

#endif
