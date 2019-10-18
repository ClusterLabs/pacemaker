/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+).
 */

#define _GNU_SOURCE

#include <pwd.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "xml.c"
#include "acl.c"

int
main(int argc, char *argv[])
{
    size_t cnt = 0;
    char **iter, **resolved;
    char uname[255];
    struct passwd *ustruct = getpwuid(geteuid());
    assert(ustruct != NULL);

    printf("which user name [%s]: ", ustruct->pw_name);
    if (fgets(uname, sizeof(uname), stdin) == NULL || *uname == '\n') {
        strncpy(uname, ustruct->pw_name, sizeof(uname) - 1);
        uname[sizeof(uname) - 1] = '\0';
    }

    printf("... sticking with user: %s\n", uname);
    iter = resolved = pcmk__selected_creds_init(uname);
    assert(resolved != NULL);

    while (*iter) {
        printf("%s%s\n", *iter++, !cnt++ ? ":" : "");
    }
    pcmk__selected_creds_free(resolved);
}
