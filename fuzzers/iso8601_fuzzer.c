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
#include <crm/common/iso8601.h>
#include <crm/common/iso8601_internal.h>


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *ns;
  char *result;
  time_t epoch;
  pcmk__time_hr_t *now;

  // Ensure we have enough data.
  if (size < 10) {
    return 0;
  }
  ns = malloc(size+1);
  memcpy(ns, data, size);
  ns[size] = '\0';

  crm_time_parse_period(ns);
  pcmk__time_hr_new(ns);

  epoch = 0;
  now = NULL;
  now = pcmk__time_hr_now(&epoch);
  result = pcmk__time_format_hr(ns, now);
  free(result);

  free(ns);  
  return 0;
}
