/*
 * Copyright 2021-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

const int capacity = 200;

static void
push(Node **head, pe_resource_t* data) {
    Node *tmp = (Node *) malloc(sizeof(Node));
    tmp->value = data;
    tmp->next = (*head);
    (*head) = tmp;
}

static int
getHash(const char *S)
{
    int i = 0;
    int r = 0;

    while(*S)
    {
        i++;
        r+=(int)(*S);
        S = S + 3;
    }

    return r % capacity;
}

static void
free_item(Node *item) {
    free(item);
}

void
init_array(struct set **array)
{
    struct set *tmp = (struct set *) malloc(capacity * sizeof(struct set));
    for (int i = 0; i < capacity; i++)
    {
        tmp[i].key = i;
        tmp[i].head = NULL;
    }
    (*array) = tmp;
}

void
free_table(struct set *array) {
    for (int i=0; i <capacity; i++) {
        Node *item = array[i].head;
        while (item != NULL) {
            Node *tmp = item->next;
            free_item(item);
            item = tmp;
        }
    }
    free(array);
}

void
insert(char* key, pe_resource_t* data, struct set *array)
{
    int index = getHash(key);
    if (array[index].head == NULL)
    {
        Node *head = NULL;
        array[index].key = index;
        push(&head, data);
        array[index].head = head;
    }
    else if (array[index].key == index)
    {
        push(&array[index].head, data);
    }
}

pe_resource_t *
find(const char* key, struct set *array)
{
    int index = getHash(key);
    if (array[index].head == 0)
    {
        return NULL;
    }
    else
    {
        Node *ptr = array[index].head;
        while (ptr != NULL)
        {
            if (!strcmp(key, ptr->value->id)) {
                return ptr->value;
            }

            ptr = ptr->next;
        }

        return NULL;
    }
}
