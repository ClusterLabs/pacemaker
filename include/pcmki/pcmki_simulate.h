/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMKI_SIMULATE__H
#  define PCMKI_SIMULATE__H

#include <crm/pengine/pe_types.h>
#include <stdbool.h>

/**
 * \brief Write out a file in dot(1) format describing the actions that will
 *        be taken by the scheduler in response to an input CIB file.
 *
 * \param[in] data_set    Working set for the cluster.
 * \param[in] dot_file    The filename to write.
 * \param[in] all_actions Write all actions, even those that are optional or
 *                        are on unmanaged resources.
 * \param[in] verbose     Add extra information, such as action IDs, to the
 *                        output.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__write_sim_dotfile(pe_working_set_t *data_set, const char *dot_file,
                            bool all_actions, bool verbose);

/**
 * \brief Profile the configuration updates and scheduler actions in a single
 *        CIB file, printing the profiling timings.
 *
 * \note \p data_set->priv must have been set to a valid \p pcmk__output_t
 *       object before this function is called.
 *
 * \param[in] xml_file The CIB file to profile.
 * \param[in] repeat   Number of times to run.
 * \param[in] data_set Working set for the cluster.
 * \param[in] use_date The date to set the cluster's time to (may
 *                     be NULL).
 */
void pcmk__profile_file(const char *xml_file, long long repeat, pe_working_set_t *data_set,
                        char *use_date);

/**
 * \brief Profile the configuration updates and scheduler actions in every
 *        CIB file in a given directory, printing the profiling timings for
 *        each.
 *
 * \note \p data_set->priv must have been set to a valid \p pcmk__output_t
 *       object before this function is called.
 *
 * \param[in] dir      A directory full of CIB files to be profiled.
 * \param[in] repeat   Number of times to run on each input file.
 * \param[in] data_set Working set for the cluster.
 * \param[in] use_date The date to set the cluster's time to (may
 *                     be NULL).
 */
void pcmk__profile_dir(const char *dir, long long repeat, pe_working_set_t *data_set,
                       char *use_date);

/**
 * \brief Set the date of the cluster, either to the value given by
 *        \p use_date, or to the "execution-date" value in the CIB.
 *
 * \note \p data_set->priv must have been set to a valid \p pcmk__output_t
 *       object before this function is called.
 *
 * \param[in,out] data_set       Working set for the cluster.
 * \param[in]     print_original If \p true, the "execution-date" should
 *                               also be printed.
 * \param[in]     use_date       The date to set the cluster's time to
 *                               (may be NULL).
 */
void pcmk__set_effective_date(pe_working_set_t *data_set, bool print_original, char *use_date);

#endif
