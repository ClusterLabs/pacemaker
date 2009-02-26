/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <crm/crm.h>
#include <crm/common/mainloop.h>

static gboolean
crm_trigger_prepare(GSource* source, gint *timeout)
{
    crm_trigger_t *trig = (crm_trigger_t*)source;
    return trig->trigger;
}

static gboolean
crm_trigger_check(GSource* source)
{
    crm_trigger_t *trig = (crm_trigger_t*)source;
    return trig->trigger;
}

/*
 *	Some kind of event occurred - notify the user.
 */
static gboolean
crm_trigger_dispatch(GSource *source, GSourceFunc callback, gpointer userdata)
{
    crm_trigger_t *trig = (crm_trigger_t*)userdata;
    trig->trigger = FALSE;

    if(callback) {
	return callback(trig->user_data);
    }
    return TRUE;
}

static GSourceFuncs crm_trigger_funcs = {
    crm_trigger_prepare,
    crm_trigger_check,
    crm_trigger_dispatch,
    NULL
};

crm_trigger_t *
mainloop_add_trigger(
    int priority, gboolean (*dispatch)(gpointer user_data), gpointer userdata)
{
    crm_trigger_t *trigger = NULL;
    GSource *source = NULL;

    CRM_ASSERT(sizeof(crm_trigger_t) > sizeof(GSource));
    
    source = g_source_new(&crm_trigger_funcs, sizeof(crm_trigger_t));

    trigger = (crm_trigger_t*) source;

    trigger->id = 0;
    trigger->trigger = FALSE;
    trigger->user_data = userdata;
    
    g_source_set_callback(source, dispatch, trigger, NULL);
    g_source_set_priority(source, priority);
    g_source_set_can_recurse(source, FALSE);

    trigger->id = g_source_attach(source, NULL);
    return trigger;
}

void 
mainloop_set_trigger(crm_trigger_t* source)
{
    source->trigger = TRUE;
}


gboolean 
mainloop_destroy_trigger(crm_trigger_t* source)
{
    source->trigger = FALSE;
    if (source->id > 0) {
	g_source_remove(source->id);
    }
    return TRUE;
}

