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
