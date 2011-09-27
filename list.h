#ifndef _LIST_H
#define _LIST_H

/**
  Simple list handlig macros.
  Needs rewrite or inclusion of /usr/include/linux/list.h as a replacement.
 */

/* Must be first if structure is going to use it. */
struct list_entry {
	struct list_entry *le_next, *le_prev;
};

#define list_head() struct list_entry _list_head

#define le(p) (&((*p)._list_head))

#define list_insert(list, newnode) \
do { \
	if (!(*list)) { \
		le(newnode)->le_next = \
		le(newnode)->le_prev = le(newnode); \
		*list = (void *)le(newnode); \
	} else { \
		le(*list)->le_prev->le_next = le(newnode); \
		le(newnode)->le_next = le(*list); \
		le(newnode)->le_prev = le(*list)->le_prev; \
		le(*list)->le_prev = le(newnode); \
	} \
} while (0)

	
#define list_prepend(list, newnode) \
do { \
	list_insert(list, newnode); \
	*list = newnode; \
} while (0)


#define list_remove(list, oldnode) \
do { \
	if (le(oldnode) == le(*list)) { \
		*list = (void *)le(*list)->le_next; \
	} \
	if (le(oldnode) == le(*list)) { \
		le(oldnode)->le_next = NULL; \
		le(oldnode)->le_prev = NULL; \
		*list = NULL; \
	} else { \
		le(oldnode)->le_next->le_prev = le(oldnode)->le_prev; \
		le(oldnode)->le_prev->le_next = le(oldnode)->le_next; \
		le(oldnode)->le_prev = NULL; \
	       	le(oldnode)->le_next = NULL; \
	} \
} while (0)

/*
   list_do(list, node) {
   	stuff;
   } while (!list_done(list, node));
 */
#define list_do(list, curr) \
	if (*list && (curr = *list)) do

#define list_done(list, curr) \
	(curr && (((curr = (void *)le(curr)->le_next)) && (curr == *list)))

/*
 * list_for(list, tmp, counter) {
 *     stuff;
 * }
 * 
 * counter = # of items in list when done.
 * * sets cnt to 0 before even checking list;
 * * checks for valid list
 * * traverses list, incrementing counter.  If we get to the for loop,
 *   there must be at least one item in the list
 */
#define list_for(list, curr, cnt) \
	if (!(cnt=0) && (list != NULL) && (*list != NULL)) \
		for (curr = *list; \
		     (cnt == 0) || (curr != *list); \
		     curr = (void*)le(curr)->le_next, \
		     cnt++)
			
#define list_for_rev(list, curr, cnt) \
	if (!(cnt=0) && list && *list) \
		for (curr = (void *)(le(*list)->le_prev); \
		     (cnt == 0) || ((void *)curr != le(*list)->le_prev); \
		     curr = (void*)(le(curr)->le_prev), \
		     cnt++)
				   

#endif
