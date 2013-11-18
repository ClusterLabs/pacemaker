/*
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_COMMON_ElECTION__H
#  define CRM_COMMON_ElECTION__H

/**
 * \file
 * \brief Functions for conducting elections
 * \ingroup core
 */

typedef struct election_s election_t;

enum election_result
{
    election_start = 0,
    election_in_progress,
    election_lost,
    election_won,
    election_error,
};

void election_fini(election_t *e);
void election_reset(election_t *e);
election_t *election_init(const char *name, const char *uname, guint period_ms, GSourceFunc cb);

void election_timeout_set_period(election_t *e, guint period_ms);
void election_timeout_stop(election_t *e);

void election_vote(election_t *e);
bool election_check(election_t *e);
void election_remove(election_t *e, const char *uname);
enum election_result election_state(election_t *e);
enum election_result election_count_vote(election_t *e, xmlNode *vote, bool can_win);

#endif
