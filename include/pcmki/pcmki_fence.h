/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMKI_STONITH_H
#  define PCMKI_STONITH_H

#  include <crm/common/output.h>
#  include <crm/stonith-ng.h>

/*!
 * \brief Perform a STONITH action.
 *
 * \note This is the internal version of pcmk_fence_action().  External users
 *       of the pacemaker API should use that function instead.
 *
 * \param[in] st        A connection to the STONITH API.
 * \param[in] target    The node receiving the action.
 * \param[in] action    The action to perform.
 * \param[in] name      Who requested the fence action?
 * \param[in] timeout   How long to wait for the operation to complete (in ms).
 * \param[in] tolerance If a successful action for \p target happened within
 *                      this many ms, return 0 without performing the action
 *                      again.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__fence_action(stonith_t *st, const char *target, const char *action,
                      const char *name, unsigned int timeout, unsigned int tolerance);

/*!
 * \brief List the fencing operations that have occurred for a specific node.
 *
 * \note This is the internal version of pcmk_fence_history().  External users
 *       of the pacemaker API should use that function instead.
 *
 * \note \p out should be initialized with pcmk__output_new() before calling this
 *       function and destroyed with out->finish and pcmk__output_free() before
 *       reusing it with any other functions in this library.
 *
 * \param[in,out] out       The output functions structure.
 * \param[in]     st        A connection to the STONITH API.
 * \param[in]     target    The node to get history for.
 * \param[in]     timeout   How long to wait for the operation to complete (in ms).
 * \param[in]     quiet     Suppress most output.
 * \param[in]     verbose   Include additional output.
 * \param[in]     broadcast Gather fencing history from all nodes.
 * \param[in]     cleanup   Clean up fencing history after listing.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__fence_history(pcmk__output_t *out, stonith_t *st, char *target,
                        unsigned int timeout, bool quiet, int verbose,
                        bool broadcast, bool cleanup);

/**
 * \brief List all installed STONITH agents.
 *
 * \note This is the internal version of pcmk_fence_installed().  External users
 *       of the pacemaker API should use that function instead.
 *
 * \note \p out should be initialized with pcmk__output_new() before calling this
 *       function and destroyed with out->finish and pcmk__output_free() before
 *       reusing it with any other functions in this library.
 *
 * \param[in,out] out     The output functions structure.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     timeout How long to wait for the operation to complete (in ms).
 *
 * \return Standard Pacemaker return code
 */
int pcmk__fence_installed(pcmk__output_t *out, stonith_t *st, unsigned int timeout);

/*!
 * \brief When was a device last fenced?
 *
 * \note This is the internal version of pcmk_fence_last().  External users
 *       of the pacemaker API should use that function instead.
 *
 * \note \p out should be initialized with pcmk__output_new() before calling this
 *       function and destroyed with out->finish and pcmk__output_free() before
 *       reusing it with any other functions in this library.
 *
 * \param[in,out] out       The output functions structure.
 * \param[in]     target    The node that was fenced.
 * \param[in]     as_nodeid 
 *
 * \return Standard Pacemaker return code
 */
int pcmk__fence_last(pcmk__output_t *out, const char *target, bool as_nodeid);

/*!
 * \brief List nodes that can be fenced.
 *
 * \note This is the internal version of pcmk_fence_list_targets().  External users
 *       of the pacemaker API should use that function instead.
 *
 * \note \p out should be initialized with pcmk__output_new() before calling this
 *       function and destroyed with out->finish and pcmk__output_free() before
 *       reusing it with any other functions in this library.
 *
 * \param[in,out] out     The output functions structure.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     agent   The agent that can do the fencing.
 * \param[in]     timeout How long to wait for the operation to complete (in ms).
 *
 * \return Standard Pacemaker return code
 */
int pcmk__fence_list_targets(pcmk__output_t *out, stonith_t *st, char *agent,
                             unsigned int timeout);

/*!
 * \brief Get metadata for a resource.
 *
 * \note This is the internal version of pcmk_fence_metadata().  External users
 *       of the pacemaker API should use that function instead.
 *
 * \note \p out should be initialized with pcmk__output_new() before calling this
 *       function and destroyed with out->finish and pcmk__output_free() before
 *       reusing it with any other functions in this library.
 *
 * \param[in,out] out     The output functions structure.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     agent   The fence agent to get metadata for.
 * \param[in]     timeout How long to wait for the operation to complete (in ms).
 *
 * \return Standard Pacemaker return code
 */
int pcmk__fence_metadata(pcmk__output_t *out, stonith_t *st, char *agent,
                         unsigned int timeout);

/*!
 * \brief List registered fence devices.
 *
 * \note This is the internal version of pcmk_fence_metadata().  External users
 *       of the pacemaker API should use that function instead.
 *
 * \note \p out should be initialized with pcmk__output_new() before calling this
 *       function and destroyed with out->finish and pcmk__output_free() before
 *       reusing it with any other functions in this library.
 *
 * \param[in,out] out     The output functions structure.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     target  If not NULL, only return devices that can fence
 *                        this node.
 * \param[in]     timeout How long to wait for the operation to complete (in ms).
 *
 * \return Standard Pacemaker return code
 */
int pcmk__fence_registered(pcmk__output_t *out, stonith_t *st, char *target,
                           unsigned int timeout);

/*!
 * \brief Register a fencing level for a specific node, node regex, or attribute.
 *
 * \note This is the internal version of pcmk_fence_register_level().  External users
 *       of the pacemaker API should use that function instead.
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
 * \return Standard Pacemaker return code
 */
int pcmk__fence_register_level(stonith_t *st, char *target, int fence_level,
                              stonith_key_value_t *devices);

/*!
 * \brief Unregister a fencing level for a specific node, node regex, or attribute.
 *
 * \note This is the internal version of pcmk_fence_unregister_level().  External users
 *       of the pacemaker API should use that function instead.
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
 * \return Standard Pacemaker return code
 */
int pcmk__fence_unregister_level(stonith_t *st, char *target, int fence_level);

/**
 * \brief Validate a STONITH device configuration.
 *
 * \note This is the internal version of pcmk_stonith_validate().  External users
 *       of the pacemaker API should use that function instead.
 *
 * \note \p out should be initialized with pcmk__output_new() before calling this
 *       function and destroyed with out->finish and pcmk__output_free() before
 *       reusing it with any other functions in this library.
 *
 * \param[in,out] out     The output functions structure.
 * \param[in]     st      A connection to the STONITH API.
 * \param[in]     agent   The agent to validate (for example, "fence_xvm").
 * \param[in]     id      STONITH device ID (may be NULL).
 * \param[in]     params  STONITH device configuration parameters.
 * \param[in]     timeout How long to wait for the operation to complete (in ms).
 *
 * \return Standard Pacemaker return code
 */
int pcmk__fence_validate(pcmk__output_t *out, stonith_t *st, const char *agent,
                         const char *id, stonith_key_value_t *params,
                         unsigned int timeout);

#endif
