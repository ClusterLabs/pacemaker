/*
 * Copyright 2021-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_SIMULATE__H
#  define PCMK__PCMKI_PCMKI_SIMULATE__H

#include <crm/common/output_internal.h>
#include <crm/pengine/pe_types.h>
#include <pcmki/pcmki_transition.h>
#include <crm/cib.h>                    // cib_t
#include <pacemaker.h>
#include <stdbool.h>
#include <stdint.h>

/*!
 * \internal
 * \brief Profile the configuration updates and scheduler actions in every
 *        CIB file in a given directory, printing the profiling timings for
 *        each.
 *
 * \note \p data_set->priv must have been set to a valid \p pcmk__output_t
 *       object before this function is called.
 *
 * \param[in]     dir      A directory full of CIB files to be profiled
 * \param[in]     repeat   Number of times to run on each input file
 * \param[in,out] data_set Working set for the cluster
 * \param[in]     use_date The date to set the cluster's time to (may be NULL)
 */
void pcmk__profile_dir(const char *dir, long long repeat, pe_working_set_t *data_set,
                       const char *use_date);

/*!
 * \internal
 * \brief Simulate executing a transition
 *
 * \param[in,out] data_set      Cluster working set
 * \param[in,out] cib           CIB object for scheduler input
 * \param[in]     op_fail_list  List of actions to simulate as failing
 *
 * \return Transition status after simulated execution
 */
enum pcmk__graph_status pcmk__simulate_transition(pe_working_set_t *data_set,
                                                  cib_t *cib,
                                                  const GList *op_fail_list);

/*!
 * \internal
 * \brief Simulate a cluster's response to events
 *
 * This high-level function essentially implements crm_simulate(8).  It operates
 * on an input CIB file and various lists of events that can be simulated.  It
 * optionally writes out a variety of artifacts to show the results of the
 * simulation.  Output can be modified with various flags.
 *
 * \param[in,out] data_set     Working set for the cluster
 * \param[in,out] out          The output functions structure
 * \param[in]     injections   A structure containing cluster events
 *                             (node up/down, tickets, injected operations)
 *                             and related data
 * \param[in]     flags        A bitfield of \p pcmk_sim_flags to modify
 *                             operation of the simulation
 * \param[in]     section_opts Which portions of the cluster status output
 *                             should be displayed?
 * \param[in]     use_date     The date to set the cluster's time to
 *                             (may be NULL)
 * \param[in]     input_file   The source CIB file, which may be overwritten by
 *                             this function (may be NULL)
 * \param[in]     graph_file   Where to write the XML-formatted transition graph
 *                             (may be NULL, in which case no file will be
 *                             written)
 * \param[in]     dot_file     Where to write the dot(1) formatted transition
 *                             graph (may be NULL, in which case no file will
 *                             be written; see \p pcmk__write_sim_dotfile())
 *
 * \return Standard Pacemaker return code
 */
int pcmk__simulate(pe_working_set_t *data_set, pcmk__output_t *out,
                   const pcmk_injections_t *injections, unsigned int flags,
                   uint32_t section_opts, const char *use_date,
                   const char *input_file, const char *graph_file,
                   const char *dot_file);

/*!
 * \internal
 *
 * If this global is set to true, simulations will add nodes to the
 * CIB configuration section, as well as the status section.
 */
extern bool pcmk__simulate_node_config;

#endif
