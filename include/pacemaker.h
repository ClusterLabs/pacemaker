/*
 * Copyright 2019-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PACEMAKER__H
#  define PCMK__PACEMAKER__H

#  include <glib.h>
#  include <libxml/tree.h>
#  include <crm/cib/cib_types.h>
#  include <crm/pengine/pe_types.h>

#  include <crm/stonith-ng.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief High Level API
 * \ingroup pacemaker
 */


/*!
 * \brief Modify operation of running a cluster simulation.
 */
enum pcmk_sim_flags {
    pcmk_sim_none             = 0,
    pcmk_sim_all_actions      = 1 << 0,
    pcmk_sim_show_pending     = 1 << 1,
    pcmk_sim_process          = 1 << 2,
    pcmk_sim_show_scores      = 1 << 3,
    pcmk_sim_show_utilization = 1 << 4,
    pcmk_sim_simulate         = 1 << 5,
    pcmk_sim_sanitized        = 1 << 6,
    pcmk_sim_verbose          = 1 << 7,
};

/*!
 * \brief Synthetic cluster events that can be injected into the cluster
 *        for running simulations.
 */
typedef struct {
    /*! A list of node names (gchar *) to simulate bringing online */
    GList *node_up;
    /*! A list of node names (gchar *) to simulate bringing offline */
    GList *node_down;
    /*! A list of node names (gchar *) to simulate failing */
    GList *node_fail;
    /*! A list of operations (gchar *) to inject.  The format of these strings
     * is described in the "Operation Specification" section of crm_simulate
     * help output.
     */
    GList *op_inject;
    /*! A list of operations (gchar *) that should return a given error code
     * if they fail.  The format of these strings is described in the
     * "Operation Specification" section of crm_simulate help output.
     */
    GList *op_fail;
    /*! A list of tickets (gchar *) to simulate granting */
    GList *ticket_grant;
    /*! A list of tickets (gchar *) to simulate revoking */
    GList *ticket_revoke;
    /*! A list of tickets (gchar *) to simulate putting on standby */
    GList *ticket_standby;
    /*! A list of tickets (gchar *) to simulate activating */
    GList *ticket_activate;
    /*! Does the cluster have an active watchdog device? */
    char *watchdog;
    /*! Does the cluster have quorum? */
    char *quorum;
} pcmk_injections_t;

/*!
 * \brief Get and output controller status
 *
 * \param[in,out] xml                 Destination for the result, as an XML tree
 * \param[in]     node_name           Name of node whose status is desired
 *                                    (\p NULL for DC)
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    \p pacemaker-controld API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 *
 * \return Standard Pacemaker return code
 */
int pcmk_controller_status(xmlNodePtr *xml, const char *node_name,
                           unsigned int message_timeout_ms);

/*!
 * \brief Get and output designated controller node name
 *
 * \param[in,out] xml                 Destination for the result, as an XML tree
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    \p pacemaker-controld API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 *
 * \return Standard Pacemaker return code
 */
int pcmk_designated_controller(xmlNodePtr *xml,
                               unsigned int message_timeout_ms);

/*!
 * \brief Free a :pcmk_injections_t structure
 *
 * \param[in,out] injections The structure to be freed
 */
void pcmk_free_injections(pcmk_injections_t *injections);

/*!
 * \brief Get and optionally output node info corresponding to a node ID from
 *        the controller
 *
 * \param[in,out] xml                 Destination for the result, as an XML tree
 * \param[in,out] node_id             ID of node whose name to get. If \p NULL
 *                                    or 0, get the local node name. If not
 *                                    \p NULL, store the true node ID here on
 *                                    success.
 * \param[out]    node_name           If not \p NULL, where to store the node
 *                                    name
 * \param[out]    uuid                If not \p NULL, where to store the node
 *                                    UUID
 * \param[out]    state               If not \p NULL, where to store the
 *                                    membership state
 * \param[out]    is_remote           If not \p NULL, where to store whether the
 *                                    node is a Pacemaker Remote node
 * \param[out]    have_quorum         If not \p NULL, where to store whether the
 *                                    node has quorum
 * \param[in]     show_output         Whether to output the node info
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    \p pacemaker-controld API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 *
 * \return Standard Pacemaker return code
 *
 * \note The caller is responsible for freeing \p *node_name, \p *uuid, and
 *       \p *state using \p free().
 */
int pcmk_query_node_info(xmlNodePtr *xml, uint32_t *node_id, char **node_name,
                         char **uuid, char **state, bool *have_quorum,
                         bool *is_remote, bool show_output,
                         unsigned int message_timeout_ms);

/*!
 * \brief Get the node name corresponding to a node ID from the controller
 *
 * \param[in,out] xml                 Destination for the result, as an XML tree
 * \param[in,out] node_id             ID of node whose name to get (or 0 for the
 *                                    local node)
 * \param[out]    node_name           If not \p NULL, where to store the node
 *                                    name
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    \p pacemaker-controld API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 *
 * \return Standard Pacemaker return code
 *
 * \note The caller is responsible for freeing \p *node_name using \p free().
 */
static inline int
pcmk_query_node_name(xmlNodePtr *xml, uint32_t node_id, char **node_name,
                     unsigned int message_timeout_ms)
{
    return pcmk_query_node_info(xml, &node_id, node_name, NULL, NULL, NULL,
                                NULL, false, message_timeout_ms);
}

/*!
 * \brief Get and output \p pacemakerd status
 *
 * \param[in,out] xml                 Destination for the result, as an XML tree
 * \param[in]     ipc_name            IPC name for request
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    \p pacemakerd API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 *
 * \return Standard Pacemaker return code
 */
int pcmk_pacemakerd_status(xmlNodePtr *xml, const char *ipc_name,
                           unsigned int message_timeout_ms);

/*!
 * \brief Calculate and output resource operation digests
 *
 * \param[out]    xml        Where to store XML with result
 * \param[in,out] rsc        Resource to calculate digests for
 * \param[in]     node       Node whose operation history should be used
 * \param[in]     overrides  Hash table of configuration parameters to override
 * \param[in]     data_set   Cluster working set (with status)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_resource_digests(xmlNodePtr *xml, pe_resource_t *rsc,
                          const pe_node_t *node, GHashTable *overrides,
                          pe_working_set_t *data_set);

/*!
 * \brief Simulate a cluster's response to events
 *
 * This high-level function essentially implements crm_simulate(8). It operates
 * on an input CIB file and various lists of events that can be simulated. It
 * optionally writes out a variety of artifacts to show the results of the
 * simulation. Output can be modified with various flags.
 *
 * \param[in,out] xml          The destination for the result, as an XML tree
 * \param[in,out] data_set     Working set for the cluster
 * \param[in]     injections   A structure containing cluster events
 *                             (node up/down, tickets, injected operations)
 * \param[in]     flags        A bitfield of :pcmk_sim_flags to modify
 *                             operation of the simulation
 * \param[in]     section_opts Which portions of the cluster status output
 *                             should be displayed?
 * \param[in]     use_date     Date to set the cluster's time to (may be NULL)
 * \param[in]     input_file   The source CIB file, which may be overwritten by
 *                             this function (may be NULL)
 * \param[in]     graph_file   Where to write the XML-formatted transition graph
 *                             (may be NULL, in which case no file will be
 *                             written)
 * \param[in]     dot_file     Where to write the dot(1) formatted transition
 *                             graph (may be NULL, in which case no file will
 *                             be written)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_simulate(xmlNodePtr *xml, pe_working_set_t *data_set,
                  const pcmk_injections_t *injections, unsigned int flags,
                  unsigned int section_opts, const char *use_date,
                  const char *input_file, const char *graph_file,
                  const char *dot_file);

/*!
 * \brief Get nodes list
 *
 * \param[in,out] xml         The destination for the result, as an XML tree
 * \param[in]     node_types  Node type(s) to return (default: all)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_nodes(xmlNodePtr *xml, const char *node_types);

/*!
 * \brief Output cluster status formatted like `crm_mon --output-as=xml`
 *
 * \param[in,out] xml  The destination for the result, as an XML tree
 *
 * \return Standard Pacemaker return code
 */
int pcmk_status(xmlNodePtr *xml);

/*!
 * \brief Check whether each rule in a list is in effect
 *
 * \param[in,out] xml       The destination for the result, as an XML tree
 * \param[in]     input     The CIB XML to check (if \c NULL, use current CIB)
 * \param[in]     date      Check whether the rule is in effect at this date and
 *                          time (if \c NULL, use current date and time)
 * \param[in]     rule_ids  The IDs of the rules to check, as a <tt>NULL</tt>-
 *                          terminated list.
 *
 * \return Standard Pacemaker return code
 */
int pcmk_check_rules(xmlNodePtr *xml, xmlNodePtr input, const crm_time_t *date,
                     const char **rule_ids);

/*!
 * \brief Check whether a given rule is in effect
 *
 * \param[in,out] xml       The destination for the result, as an XML tree
 * \param[in]     input     The CIB XML to check (if \c NULL, use current CIB)
 * \param[in]     date      Check whether the rule is in effect at this date and
 *                          time (if \c NULL, use current date and time)
 * \param[in]     rule_ids  The ID of the rule to check
 *
 * \return Standard Pacemaker return code
 */
static inline int
pcmk_check_rule(xmlNodePtr *xml, xmlNodePtr input, const crm_time_t *date,
                const char *rule_id)
{
    const char *rule_ids[] = {rule_id, NULL};
    return pcmk_check_rules(xml, input, date, rule_ids);
}

/*!
 * \enum pcmk_rc_disp_flags
 * \brief Bit flags to control which fields of result code info are displayed
 */
enum pcmk_rc_disp_flags {
    pcmk_rc_disp_none = 0,          //!< (Does nothing)
    pcmk_rc_disp_code = (1 << 0),   //!< Display result code number
    pcmk_rc_disp_name = (1 << 1),   //!< Display result code name
    pcmk_rc_disp_desc = (1 << 2),   //!< Display result code description
};

/*!
 * \brief Display the name and/or description of a result code
 *
 * \param[in,out] xml    The destination for the result, as an XML tree
 * \param[in]     code   The result code
 * \param[in]     type   Interpret \c code as this type of result code.
 *                       Supported values: \c pcmk_result_legacy,
 *                       \c pcmk_result_rc, \c pcmk_result_exitcode.
 * \param[in]     flags  Group of \c pcmk_rc_disp_flags
 *
 * \return Standard Pacemaker return code
 */
int pcmk_show_result_code(xmlNodePtr *xml, int code, enum pcmk_result_type type,
                          uint32_t flags);

/*!
 * \brief List all valid result codes in a particular family
 *
 * \param[in,out] xml    The destination for the result, as an XML tree
 * \param[in]     type   The family of result codes to list. Supported
 *                       values: \c pcmk_result_legacy, \c pcmk_result_rc,
 *                       \c pcmk_result_exitcode.
 * \param[in]     flags  Group of \c pcmk_rc_disp_flags
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_result_codes(xmlNodePtr *xml, enum pcmk_result_type type,
                           uint32_t flags);

#ifdef BUILD_PUBLIC_LIBPACEMAKER

/*!
 * \brief Ask the cluster to perform fencing
 *
 * \param[in,out] st        A connection to the fencer API
 * \param[in]     target    The node that should be fenced
 * \param[in]     action    The fencing action (on, off, reboot) to perform
 * \param[in]     name      Who requested the fence action?
 * \param[in]     timeout   How long to wait for operation to complete (in ms)
 * \param[in]     tolerance If a successful action for \p target happened within
 *                          this many ms, return 0 without performing the action
 *                          again
 * \param[in]     delay     Apply this delay (in milliseconds) before initiating
 *                          fencing action (-1 applies no delay and also
 *                          disables any fencing delay from pcmk_delay_base and
 *                          pcmk_delay_max)
 * \param[out]     reason   If not NULL, where to put descriptive failure reason
 *
 * \return Standard Pacemaker return code
 * \note If \p reason is not NULL, the caller is responsible for freeing its
 *       returned value.
 */
int pcmk_request_fencing(stonith_t *st, const char *target, const char *action,
                         const char *name, unsigned int timeout,
                         unsigned int tolerance, int delay, char **reason);

/*!
 * \brief List the fencing operations that have occurred for a specific node
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml       The destination for the result, as an XML tree
 * \param[in,out] st        A connection to the fencer API
 * \param[in]     target    The node to get history for
 * \param[in]     timeout   How long to wait for operation to complete (in ms)
 * \param[in]     quiet     Suppress most output
 * \param[in]     verbose   Include additional output
 * \param[in]     broadcast Gather fencing history from all nodes
 * \param[in]     cleanup   Clean up fencing history after listing
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_history(xmlNodePtr *xml, stonith_t *st, const char *target,
                       unsigned int timeout, bool quiet, int verbose,
                       bool broadcast, bool cleanup);

/*!
 * \brief List all installed fence agents
 *
 * \param[in,out] xml      The destination for the result, as an XML tree (if
 *                         not NULL, previous contents will be freed and lost)
 * \param[in,out] st       A connection to the fencer API
 * \param[in]     timeout  How long to wait for operation to complete (in ms)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_installed(xmlNodePtr *xml, stonith_t *st, unsigned int timeout);

/*!
 * \brief When was a device last fenced?
 *
 * \param[in,out] xml        The destination for the result, as an XML tree (if
 *                           not NULL, previous contents will be freed and lost)
 * \param[in]     target     The node that was fenced
 * \param[in]     as_nodeid  If true, \p target has node ID rather than name
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_last(xmlNodePtr *xml, const char *target, bool as_nodeid);

/*!
 * \brief List nodes that can be fenced
 *
 * \param[in,out] xml        The destination for the result, as an XML tree (if
 *                           not NULL, previous contents will be freed and lost)
 * \param[in,out] st         A connection to the fencer API
 * \param[in]     device_id  Resource ID of fence device to check
 * \param[in]     timeout    How long to wait for operation to complete (in ms)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_list_targets(xmlNodePtr *xml, stonith_t *st,
                            const char *device_id, unsigned int timeout);

/*!
 * \brief Get metadata for a fence agent
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml      The destination for the result, as an XML tree (if
 *                         not NULL, previous contents will be freed and lost)
 * \param[in,out] st       A connection to the fencer API
 * \param[in]     agent    The fence agent to get metadata for
 * \param[in]     timeout  How long to wait for operation to complete (in ms)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_metadata(xmlNodePtr *xml, stonith_t *st, const char *agent,
                        unsigned int timeout);

/*!
 * \brief List registered fence devices
 *
 * \param[in,out] xml      The destination for the result, as an XML tree (if
 *                         not NULL, previous contents will be freed and lost)
 * \param[in,out] st       A connection to the fencer API
 * \param[in]     target   If not NULL, return only devices that can fence this
 * \param[in]     timeout  How long to wait for operation to complete (in ms)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_registered(xmlNodePtr *xml, stonith_t *st, const char *target,
                          unsigned int timeout);

/*!
 * \brief Register a fencing topology level
 *
 * \param[in,out] st           A connection to the fencer API
 * \param[in]     target       What fencing level targets (as "name=value" to
 *                             target by given node attribute, or "@pattern" to
 *                             target by node name pattern, or a node name)
 * \param[in]     fence_level  Index number of level to add
 * \param[in]     devices      Devices to use in level
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_register_level(stonith_t *st, const char *target,
                              int fence_level,
                              const stonith_key_value_t *devices);

/*!
 * \brief Unregister a fencing topology level
 *
 * \param[in,out] st           A connection to the fencer API
 * \param[in]     target       What fencing level targets (as "name=value" to
 *                             target by given node attribute, or "@pattern" to
 *                             target by node name pattern, or a node name)
 * \param[in]     fence_level  Index number of level to remove
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_unregister_level(stonith_t *st, const char *target,
                                int fence_level);

/*!
 * \brief Validate a fence device configuration
 *
 * \param[in,out] xml      The destination for the result, as an XML tree (if
 *                         not NULL, previous contents will be freed and lost)
 * \param[in,out] st       A connection to the fencer API
 * \param[in]     agent    The agent to validate (for example, "fence_xvm")
 * \param[in]     id       Fence device ID (may be NULL)
 * \param[in]     params   Fence device configuration parameters
 * \param[in]     timeout  How long to wait for operation to complete (in ms)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_validate(xmlNodePtr *xml, stonith_t *st, const char *agent,
                        const char *id, const stonith_key_value_t *params,
                        unsigned int timeout);
#endif

#ifdef __cplusplus
}
#endif

#endif
