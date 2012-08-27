/* 
 * Copyright (C) 2005 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * http://en.wikipedia.org/wiki/ISO_8601 as at 2005-08-01
 *
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <time.h>
#include <ctype.h>
#include <crm/common/iso8601.h>

struct ha_time_s {
        int years;
        int months; /* Only for durations */
        int days;
        int seconds;

        struct ha_time_s *offset;
};

static uint32_t get_ordinal_days(uint32_t y, uint32_t m, uint32_t d)
{
    int lpc;
    for(lpc = 1; lpc < m; lpc++) {
        d += days_per_month(lpc, y);
    }
    return d;
}

void
add_seconds(ha_time_t * a_time, int extra)
{
    int days = 0;
    int seconds = 24 * 60 * 60;

    crm_trace("Adding %d seconds to %d (max=%d)", extra, a_time->seconds, seconds);
    if(extra < 0) {
        sub_seconds(a_time, -extra);
        return;
    }

    a_time->seconds += extra;
    while (a_time->seconds >= seconds) {
        a_time->seconds -= seconds;
        days++;
    }
    add_days(a_time, days);
}

void
add_days(ha_time_t * a_time, int extra)
{
    int ydays = is_leap_year(a_time->years)?366:365;

    crm_trace("Adding %d days to %.4d-%.3d",
              extra, a_time->years, a_time->days);
    if(extra < 0) {
        sub_days(a_time, -extra);
        return;
    }
    
    a_time->days += extra;
    while (a_time->days > ydays) {
        a_time->years++;
        a_time->days -= ydays;
        ydays = is_leap_year(a_time->years)?366:365;
    }
}

void
add_months(ha_time_t * a_time, int extra)
{
    int lpc;
    uint32_t y, m, d, dmax;

    crm_get_gregorian_date(a_time, &y, &m, &d);
    crm_trace("Adding %d months to %.4d-%.2d-%.2d", extra, y, m, d);
    if(extra < 0) {
        sub_months(a_time, -extra);
        return;
    }

    for(lpc = extra; lpc > 0; lpc--) {
        m++;
        if(m == 13) {
            m = 1;
            y++;
        }
    }

    dmax = days_per_month(m, y);
    if(dmax < d) {
        /* Preserve day-of-month unless the month doesn't have enough days */
        d = dmax;
    }

    crm_trace("Calculated %.4d-%.2d-%.2d", y, m, d);
    
    a_time->years = y;
    a_time->days = get_ordinal_days(y, m, d);

    crm_get_gregorian_date(a_time, &y, &m, &d);
    crm_trace("Got %.4d-%.2d-%.2d", y, m, d);
}

void
sub_seconds(ha_time_t * a_time, int extra)
{
    int days = 0;

    crm_trace("Subtracting %d seconds from %d", extra, a_time->seconds);
    if(extra < 0) {
        add_seconds(a_time, -extra);
        return;
    }

    a_time->seconds -= extra;
    crm_trace("s=%d, d=%d", a_time->seconds, days);

    while (a_time->seconds < 0) {
        crm_trace("s=%d, d=%d", a_time->seconds, days);
        a_time->seconds += 24 * 60 * 60;
        days++;
        crm_trace("s=%d, d=%d", a_time->seconds, days);
    }
    sub_days(a_time, days);
}

void
sub_days(ha_time_t * a_time, int extra)
{
    crm_trace("Subtracting %d days from %.4d-%.3d",
              extra, a_time->years, a_time->days);
    if(extra < 0) {
        add_days(a_time, -extra);
        return;
    }

    a_time->days -= extra;
    while (a_time->days <= 0) {
        a_time->years--;
        a_time->days += is_leap_year(a_time->years)?366:365;
    }
}

void
sub_months(ha_time_t * a_time, int extra)
{
    int lpc;
    uint32_t y, m, d, dmax;
    crm_get_gregorian_date(a_time, &y, &m, &d);

    crm_trace("Subtracting %d months from %.4d-%.2d-%.2d", extra, y, m, d);
    if(extra < 0) {
        add_months(a_time, -extra);
        return;
    }    

    for(lpc = extra; lpc > 0; lpc--) {
        m--;
        if(m == 0) {
            m = 12;
            y--;
        }
    }

    dmax = days_per_month(m, y);
    if(dmax < d) {
        /* Preserve day-of-month unless the month doesn't have enough days */
        d = dmax;
    }
    crm_trace("Calculated %.4d-%.2d-%.2d", y, m, d);

    a_time->years = y;
    a_time->days = get_ordinal_days(y, m, d);

    crm_get_gregorian_date(a_time, &y, &m, &d);
    crm_trace("Got %.4d-%.2d-%.2d", y, m, d);
}

void
add_minutes(ha_time_t * a_time, int extra)
{
    add_seconds(a_time, extra * 60);
}

void
add_hours(ha_time_t * a_time, int extra)
{
    add_seconds(a_time, extra * 60 * 60);
}

void
add_weeks(ha_time_t * a_time, int extra)
{
    add_days(a_time, extra * 7);
}

void
add_years(ha_time_t * a_time, int extra)
{
    a_time->years += extra;
}

void
sub_minutes(ha_time_t * a_time, int extra)
{
    sub_seconds(a_time, extra * 60);
}

void
sub_hours(ha_time_t * a_time, int extra)
{
    sub_seconds(a_time, extra * 60 * 60);
}

void
sub_weeks(ha_time_t * a_time, int extra)
{
    sub_days(a_time, 7 * extra);
}

void
sub_years(ha_time_t * a_time, int extra)
{
    a_time->years -= extra;
}

