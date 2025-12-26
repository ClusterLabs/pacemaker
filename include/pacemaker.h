/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PACEMAKER__H
#  define PCMK__PACEMAKER__H

#  include <stdbool.h>
#  include <stdint.h>              // UINT32_C

#  include <glib.h>
#  include <libxml/tree.h>

#  include <crm/common/scheduler.h>
#  include <crm/cib/cib_types.h>

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
    pcmk_sim_all_actions      = UINT32_C(1) << 0,
    pcmk_sim_show_pending     = UINT32_C(1) << 1,
    pcmk_sim_process          = UINT32_C(1) << 2,
    pcmk_sim_show_scores      = UINT32_C(1) << 3,
    pcmk_sim_show_utilization = UINT32_C(1) << 4,
    pcmk_sim_simulate         = UINT32_C(1) << 5,
    pcmk_sim_sanitized        = UINT32_C(1) << 6,
    pcmk_sim_verbose          = UINT32_C(1) << 7,
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
 *                                    controller API. If 0,
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
 *                                    controller API. If 0,
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
 *                                    controller API. If 0,
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
 *                                    controller API. If 0,
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
 * \brief Remove a resource
 *
 * \param[in,out] xml   Destination for the result, as an XML tree
 * \param[in] rsc_id    Resource to remove
 * \param[in] rsc_type  Type of the resource ("primitive", "group", etc.)
 *
 * \return Standard Pacemaker return code
 * \note This function will return \p pcmk_rc_ok if \p rsc_id doesn't exist
 *       or if \p rsc_type is incorrect for \p rsc_id (deleting something
 *       that doesn't exist always succeeds).
 */
int pcmk_resource_delete(xmlNodePtr *xml, const char *rsc_id, const char *rsc_type);

/*!
 * \brief Calculate and output resource operation digests
 *
 * \param[out]    xml        Where to store XML with result
 * \param[in,out] rsc        Resource to calculate digests for
 * \param[in]     node       Node whose operation history should be used
 * \param[in]     overrides  Hash table of configuration parameters to override
 *
 * \return Standard Pacemaker return code
 */
int pcmk_resource_digests(xmlNodePtr *xml, pcmk_resource_t *rsc,
                          const pcmk_node_t *node, GHashTable *overrides);

/*!
 * \brief Simulate a cluster's response to events
 *
 * This high-level function essentially implements crm_simulate(8). It operates
 * on an input CIB file and various lists of events that can be simulated. It
 * optionally writes out a variety of artifacts to show the results of the
 * simulation. Output can be modified with various flags.
 *
 * \param[in,out] xml          The destination for the result, as an XML tree
 * \param[in,out] scheduler    Scheduler data
 * \param[in]     injections   A structure containing cluster events
 *                             (node up/down, tickets, injected operations)
 * \param[in]     flags        Group of <tt>enum pcmk_sim_flags</tt>
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
int pcmk_simulate(xmlNodePtr *xml, pcmk_scheduler_t *scheduler,
                  const pcmk_injections_t *injections, unsigned int flags,
                  unsigned int section_opts, const char *use_date,
                  const char *input_file, const char *graph_file,
                  const char *dot_file);

/*!
 * \brief Verify that a CIB is error-free or output errors and warnings
 *
 * This high-level function essentially implements crm_verify(8). It operates
 * on an input CIB file, which can be inputted through one of several ways. It
 * writes out XML-formatted output.
 *
 * \param[in,out] xml          The destination for the result, as an XML tree
 * \param[in]     cib_source   Source of the CIB: 
 *                             NULL -> use live cib, "-" -> stdin
 *                             "<..." -> xml str, otherwise -> xml file name
 *
 * \return Standard Pacemaker return code
 */
int pcmk_verify(xmlNodePtr *xml, const char *cib_source);

/*!
 * \brief Output list of nodes from the CIB
 *
 * \param[in,out] xml    The destination for the result, as an XML tree
 * \param[in]     types  Comma-separated list of node types to return. Valid
 *                       types: \c "all", \c "cluster", \c "guest", \c "remote".
 *                       A value of \c NULL is equivalent to \c "all".
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_nodes(xmlNode **xml, const char *types);

/*!
 * \brief Output cluster status formatted like `crm_mon --output-as=xml`
 *
 * \param[in,out] xml  The destination for the result, as an XML tree
 *
 * \return Standard Pacemaker return code
 */
int pcmk_status(xmlNodePtr *xml);

// @COMPAT Change rule_ids to type const char *const * at a compatibility break
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

//! Bit flags to control which fields of result code info are displayed
enum pcmk_rc_disp_flags {
    //! (Does nothing)
    pcmk_rc_disp_none = 0,

    //! Display result code number
    pcmk_rc_disp_code = (UINT32_C(1) << 0),

    //! Display result code name
    pcmk_rc_disp_name = (UINT32_C(1) << 1),

    //! Display result code description
    pcmk_rc_disp_desc = (UINT32_C(1) << 2),
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

/*!
 * \brief List available providers for the given OCF agent
 *
 * \param[in,out] xml        The destination for the result, as an XML tree
 * \param[in]     agent_spec Resource agent name
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_alternatives(xmlNodePtr *xml, const char *agent_spec);

/*!
 * \brief List all agents available for the named standard and/or provider
 *
 * \param[in,out] xml        The destination for the result, as an XML tree
 * \param[in]     agent_spec STD[:PROV]
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_agents(xmlNodePtr *xml, char *agent_spec);

/*!
 * \brief List all available OCF providers for the given agent
 *
 * \param[in,out] xml        The destination for the result, as an XML tree
 * \param[in]     agent_spec Resource agent name
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_providers(xmlNodePtr *xml, const char *agent_spec);

/*!
 * \brief List all available resource agent standards
 *
 * \param[in,out] xml        The destination for the result, as an XML tree
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_standards(xmlNodePtr *xml);

/*!
 * \brief List all available cluster options
 *
 * These are options that affect the entire cluster.
 *
 * \param[in,out] xml  The destination for the result, as an XML tree
 * \param[in]     all  If \c true, include advanced and deprecated options
 *                     (currently always treated as true)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_cluster_options(xmlNode **xml, bool all);

/*!
 * \brief List common fencing resource parameters
 *
 * These are parameters that are available for all fencing resources, regardless
 * of type. They are processed by Pacemaker, rather than by the fence agent or
 * the fencing library.
 *
 * \param[in,out] xml  The destination for the result, as an XML tree
 * \param[in]     all  If \c true, include advanced and deprecated options
 *                     (currently always treated as true)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_fencing_params(xmlNode **xml, bool all);

/*!
 * \internal
 * \brief List meta-attributes applicable to primitive resources as OCF-like XML
 *
 * \param[in,out] out  Output object
 * \param[in]     all  If \c true, include advanced and deprecated options (this
 *                     is always treated as true for XML output objects)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_list_primitive_meta(xmlNode **xml, bool all);

/*!
 * \brief Return constraints that apply to the given ticket
 *
 * \param[in,out] xml           The destination for the result, as an XML tree
 * \param[in]     ticket_id     Ticket to find constraint for, or \c NULL for
 *                              all ticket constraints
 *
 * \return Standard Pacemaker return code
 */
int pcmk_ticket_constraints(xmlNodePtr *xml, const char *ticket_id);


/*!
 * \brief Delete a ticket's state from the local cluster site
 *
 * \param[in,out] xml       The destination for the result, as an XML tree
 * \param[in]     ticket_id Ticket to delete
 * \param[in]     force     If \c true, delete the ticket even if it has
 *                          been granted
 *
 * \return Standard Pacemaker return code
 */
int pcmk_ticket_delete(xmlNodePtr *xml, const char *ticket_id, bool force);

/*!
 * \brief Return the value of a ticket's attribute
 *
 * \param[in,out] xml           The destination for the result, as an XML tree
 * \param[in]     ticket_id     Ticket to find attribute value for
 * \param[in]     attr_name     Attribute's name to find value for
 * \param[in]     attr_default  If either the ticket or the attribute do not
 *                              exist, use this as the value in \p xml
 *
 * \return Standard Pacemaker return code
 */
int pcmk_ticket_get_attr(xmlNodePtr *xml, const char *ticket_id,
                         const char *attr_name, const char *attr_default);

/*!
 * \brief Return information about the given ticket
 *
 * \param[in,out] xml           The destination for the result, as an XML tree
 * \param[in]     ticket_id     Ticket to find info value for, or \c NULL for
 *                              all tickets
 *
 * \return Standard Pacemaker return code
 */
int pcmk_ticket_info(xmlNodePtr *xml, const char *ticket_id);

/*!
 * \brief Remove the given attribute(s) from a ticket
 *
 * \param[in,out] xml           The destination for the result, as an XML tree
 * \param[in]     ticket_id     Ticket to remove attributes from
 * \param[in]     attr_delete   A list of attribute names
 * \param[in]     force         Attempting to remove the granted attribute of
 *                              \p ticket_id will cause this function to return
 *                              \c EACCES unless \p force is set to \c true
 *
 * \return Standard Pacemaker return code
 */
int pcmk_ticket_remove_attr(xmlNodePtr *xml, const char *ticket_id, GList *attr_delete,
                            bool force);

/*!
 * \brief Set the given attribute(s) on a ticket
 *
 * \param[in,out] xml           The destination for the result, as an XML tree
 * \param[in]     ticket_id     Ticket to set attributes on
 * \param[in]     attr_set      A hash table of attributes, where keys are the
 *                              attribute names and the values are the attribute
 *                              values
 * \param[in]     force         Attempting to change the granted status of
 *                              \p ticket_id will cause this function to return
 *                              \c EACCES unless \p force is set to \c true
 *
 * \return Standard Pacemaker return code
 *
 * \note If no \p ticket_id attribute exists but \p attr_set is non-NULL, the
 *       ticket will be created with the given attributes.
 */
int pcmk_ticket_set_attr(xmlNodePtr *xml, const char *ticket_id, GHashTable *attr_set,
                         bool force);

/*!
 * \brief Return a ticket's state XML
 *
 * \param[in,out] xml           The destination for the result, as an XML tree
 * \param[in]     ticket_id     Ticket to find state for, or \c NULL for all
 *                              tickets
 *
 * \return Standard Pacemaker return code
 *
 * \note If \p ticket_id is not \c NULL and more than one ticket exists with
 *       that ID, this function returns \c pcmk_rc_duplicate_id.
 */
int pcmk_ticket_state(xmlNodePtr *xml, const char *ticket_id);

/*!
 * \brief Ask the cluster to perform fencing
 *
 * \param[in,out] xml       The destination for the result, as an XML tree
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
int pcmk_request_fencing(xmlNodePtr *xml, const char *target, const char *action,
                         const char *name, unsigned int timeout,
                         unsigned int tolerance, int delay, char **reason);

/*!
 * \brief List the fencing operations that have occurred for a specific node
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml       The destination for the result, as an XML tree
 * \param[in]     target    The node to get history for
 * \param[in]     timeout   How long to wait for operation to complete (in ms)
 * \param[in]     quiet     Suppress most output
 * \param[in]     verbose   Include additional output
 * \param[in]     broadcast Gather fencing history from all nodes
 * \param[in]     cleanup   Clean up fencing history after listing
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_history(xmlNodePtr *xml, const char *target, unsigned int timeout,
                       bool quiet, int verbose, bool broadcast, bool cleanup);

/*!
 * \brief List all installed fence agents
 *
 * \param[in,out] xml      The destination for the result, as an XML tree (if
 *                         not NULL, previous contents will be freed and lost)
 * \param[in]     timeout  Ignored
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_installed(xmlNodePtr *xml, unsigned int timeout);

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
 * \param[in]     device_id  Resource ID of fence device to check
 * \param[in]     timeout    How long to wait for operation to complete (in ms)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_list_targets(xmlNodePtr *xml, const char *device_id,
                            unsigned int timeout);

/*!
 * \brief Get metadata for a fence agent
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml      The destination for the result, as an XML tree (if
 *                         not NULL, previous contents will be freed and lost)
 * \param[in]     agent    The fence agent to get metadata for
 * \param[in]     timeout  How long to wait for operation to complete (in ms)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_metadata(xmlNodePtr *xml, const char *agent, unsigned int timeout);

/*!
 * \brief List registered fence devices
 *
 * \param[in,out] xml      The destination for the result, as an XML tree (if
 *                         not NULL, previous contents will be freed and lost)
 * \param[in]     target   If not NULL, return only devices that can fence this
 * \param[in]     timeout  How long to wait for operation to complete (in ms)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_registered(xmlNodePtr *xml, const char *target, unsigned int timeout);

/*!
 * \brief Register a fencing topology level
 *
 * \param[in,out] xml          The destination for the result, as an XML tree (if
 *                             not NULL, previous contents will be freed and lost)
 * \param[in]     target       What fencing level targets (as "name=value" to
 *                             target by given node attribute, or "@pattern" to
 *                             target by node name pattern, or a node name)
 * \param[in]     fence_level  Index number of level to add
 * \param[in]     devices      Devices to use in level as a list of char *
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_register_level(xmlNodePtr *xml, const char *target, int fence_level,
                              GList *devices);

/*!
 * \brief Unregister a fencing topology level
 *
 * \param[in,out] xml          The destination for the result, as an XML tree (if
 *                             not NULL, previous contents will be freed and lost)
 * \param[in]     target       What fencing level targets (as "name=value" to
 *                             target by given node attribute, or "@pattern" to
 *                             target by node name pattern, or a node name)
 * \param[in]     fence_level  Index number of level to remove
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_unregister_level(xmlNodePtr *xml, const char *target, int fence_level);

/*!
 * \brief Validate a fence device configuration
 *
 * \param[in,out] xml      The destination for the result, as an XML tree (if
 *                         not NULL, previous contents will be freed and lost)
 * \param[in]     agent    The agent to validate (for example, "fence_xvm")
 * \param[in]     id       Fence device ID (may be NULL)
 * \param[in]     params   Fence device configuration parameters
 * \param[in]     timeout  How long to wait for operation to complete (in ms)
 *
 * \return Standard Pacemaker return code
 */
int pcmk_fence_validate(xmlNodePtr *xml, const char *agent, const char *id,
                        GHashTable *params, unsigned int timeout);

#ifdef __cplusplus
}
#endif

#endif
