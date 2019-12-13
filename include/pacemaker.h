/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PACEMAKER__H
#  define PACEMAKER__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief High Level API
 * \ingroup pacemaker
 */

#  include <crm/stonith-ng.h>
#  include <libxml/tree.h>

/*!
 * \brief Perform a STONITH action.
 *
 * \param[in] st        A connection to the STONITH API.
 * \param[in] target    The node receiving the action.
 * \param[in] action    The action to perform.
 * \param[in] name      Who requested the fence action?
 * \param[in] timeout   How long to wait for the operation to complete (in seconds).
 * \param[in] tolerance If a successful action for \p target happened within
 *                      this many seconds, return 0 without performing the
 *                      action again.
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_action(stonith_t *st, const char *target, const char *action,
                      const char *name, int timeout, int tolerance);

/*!
 * \brief List the fencing operations that have occurred for a specific node.
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml       The destination for the result, as an XML tree.
 * \param[in]     st        A connection to the STONITH API.
 * \param[in]     target    The node to get history for.
 * \param[in]     timeout   How long to wait for the operation to complete (in seconds).
 * \param[in]     quiet     Suppress most output.
 * \param[in]     verbose   Include additional output.
 * \param[in]     broadcast Gather fencing history from all nodes.
 * \param[in]     cleanup   Clean up fencing history after listing.
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_history(xmlNodePtr *xml, stonith_t *st, char *target, int timeout,
                       bool quiet, int verbose, bool broadcast, bool cleanup);

/*!
 * \brief List all installed STONITH agents.
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml     The destination for the result, as an XML tree.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     timeout How long to wait for the operation to complete (in seconds).
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_installed(xmlNodePtr *xml, stonith_t *st, int timeout);

/*!
 * \brief When was a device last fenced?
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml       The destination for the result, as an XML tree.
 * \param[in]     target    The node that was fenced.
 * \param[in]     as_nodeid 
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_last(xmlNodePtr *xml, const char *target, bool as_nodeid);

/*!
 * \brief List nodes that can be fenced.
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml     The destination for the result, as an XML tree.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     agent   The agent that can do the fencing.
 * \param[in]     timeout How long to wait for the operation to complete (in seconds).
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_list_targets(xmlNodePtr *xml, stonith_t *st, char *agent, int timeout);

/*!
 * \brief Get metadata for a resource.
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml     The destination for the result, as an XML tree.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     agent   The fence agent to get metadata for.
 * \param[in]     timeout How long to wait for the operation to complete (in seconds).
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_metadata(xmlNodePtr *xml, stonith_t *st, char *agent, int timeout);

/*!
 * \brief List registered fence devices.
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml     The destination for the result, as an XML tree.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     target  If not NULL, only return devices that can fence
 *                        this node.
 * \param[in]     timeout How long to wait for the operation to complete (in seconds).
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_registered(xmlNodePtr *xml, stonith_t *st, char *target, int timeout);

/*!
 * \brief Register a fencing level for a specific node, node regex, or attribute.
 *
 * \p target can take three different forms:
 *   - name=value, in which case \p target is an attribute.
 *   - @pattern, in which case \p target is a node regex.
 *   - Otherwise, \p target is a node name.
 *
 * \param[in] st          A connection to the STONITH API.
 * \param[in] target      The object to register a fencing level for.
 * \param[in] fence_level Index number of level to add.
 * \param[in] devices     Devices to use in level.
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_register_level(stonith_t *st, char *target, int fence_level,
                              stonith_key_value_t *devices);

/*!
 * \brief Unregister a fencing level for a specific node, node regex, or attribute.
 *
 * \p target can take three different forms:
 *   - name=value, in which case \p target is an attribute.
 *   - @pattern, in which case \p target is a node regex.
 *   - Otherwise, \p target is a node name.
 *
 * \param[in] st          A connection to the STONITH API.
 * \param[in] target      The object to unregister a fencing level for.
 * \param[in] fence_level Index number of level to remove.
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_unregister_level(stonith_t *st, char *target, int fence_level);

/*!
 * \brief Validate a STONITH device configuration.
 *
 * \note If \p xml is not NULL, it will be freed first and the previous
 *       contents lost.
 *
 * \param[in,out] xml     The destination for the result, as an XML tree.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     agent   The agent to validate (for example, "fence_xvm").
 * \param[in]     id      STONITH device ID (may be NULL).
 * \param[in]     params  STONITH device configuration parameters.
 * \param[in]     timeout How long to wait for the operation to complete (in seconds).
 *
 * \return 0 on success, or various error codes on error.
 */
int pcmk_fence_validate(xmlNodePtr *xml, stonith_t *st, const char *agent,
                        const char *id, stonith_key_value_t *params, int timeout);

#ifdef __cplusplus
}
#endif

#endif
