/*
 * Copyright 2023-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_OPERATION__H
#define BASED_OPERATION__H

#include <crm/cib/internal.h>       // cib__*

cib__op_fn_t based_get_op_function(const cib__operation_t *operation);

#endif // BASED_OPERATION__H
