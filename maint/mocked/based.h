/*
 * Copyright 2019-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * Licensed under the GNU General Public License version 2 or later (GPLv2+).
 */

#pragma once

#include <stdlib.h>  /* size_t */
#include <stdbool.h>  /* bool */

#include <crm/common/ipc_internal.h>  /* pcmk__client_t */


struct module_s;

typedef struct mock_based_context_s {
    size_t modules_cnt;
    struct module_s** modules;
} mock_based_context_t;


typedef int (*mock_based_argparse_hook)(mock_based_context_t *,
                                        bool, int,
                                        const char *[]);

typedef void (*mock_based_destroy_hook)(struct module_s *);

/* specialized callbacks... */
typedef void (*mock_based_cib_notify_hook)(pcmk__client_t *);

typedef struct mock_based_hooks_s {
    /* generic ones */
    mock_based_argparse_hook argparse;
    mock_based_destroy_hook destroy;

    /* specialized callbacks... */
    mock_based_cib_notify_hook cib_notify;
} mock_based_hooks_t;

typedef struct module_s {
    char shortopt;
    mock_based_hooks_t hooks;
    void *priv;
} module_t;

size_t mock_based_register_module(module_t mod);
