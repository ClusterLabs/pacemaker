/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <crm/cib/internal.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];

  // Have at least some data
  if (size < 5) {
    return 0;
  }

  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp)
    return 0;
  fwrite(data, size, 1, fp);
  fclose(fp);

  cib_file_read_and_verify(filename, filename, NULL);

  unlink(filename);

  return 0;
}
