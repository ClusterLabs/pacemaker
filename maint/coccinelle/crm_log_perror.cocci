/*
 * Copyright 2019 Red Hat, Inc.
 * Author: Jan Pokorny <jpokorny@redhat.com>
 * Part of pacemaker project
 * SPDX-License-Identifier: FSFAP
 *
 * As a rule of thumb, we require that crm_log_perror instead of crm_perror
 * that usually incurs redundancy/wasted effort.  The only explicit exception
 * is logging.c file since it's use of crm_perror may happen before the
 * logging being set up.
 *
 * Known issues: doesn't currently work inside CRM_ASSERT macro.
 */

@crm_perror_turned_crm_log_perror depends on
 !(file in "lib/common/logging.c" || file in "common/logging.c")@
@@
- crm_perror
+ crm_log_perror
  (...);
