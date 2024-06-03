/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <crm/common/util.h>
#include <crm/common/util_compat.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *ns;
  guint result;

  if (size < 10) {
    return 0;
  }
  ns = malloc(size+1);
  memcpy(ns, data, size);
  ns[size] = '\0';

  pcmk_parse_interval_spec(ns, &result);

  free(ns);  
  return 0;
}
