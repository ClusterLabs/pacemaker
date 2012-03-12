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

#define do_add_field(atime, field, extra, limit, overflow)		\
	{								\
		crm_trace("Adding %d to %d (limit=%d)",		\
			    extra, atime->field, limit);		\
		atime->field += extra;					\
		if(limit > 0) {						\
			while(limit < atime->field) {			\
				crm_trace("Overflowing: %d", atime->field); \
				atime->field -= limit;			\
				overflow(atime, 1);			\
			}						\
		}							\
		atime->field = atime->field;				\
		crm_trace("Result: %d", atime->field);		\
	}

#define do_add_days_field(atime, field, extra, overflow)		\
	{								\
		int __limit = days_per_month(atime->months, atime->years);	\
		crm_trace("Adding %d to %d (limit=%d)",		\
			    extra, atime->field, __limit);		\
		atime->field += extra;					\
		if(__limit > 0) {						\
			while(__limit < atime->field) {			\
				crm_trace("Overflowing: %d", atime->field); \
				overflow(atime, 1);			\
				__limit = days_per_month(atime->months, atime->years);	\
				atime->field -= __limit;			\
			}						\
		}							\
		atime->field = atime->field;				\
		crm_trace("Result: %d", atime->field);		\
	}

#define do_add_time_field(atime, field, extra, limit, overflow)		\
	{								\
		crm_trace("Adding %d to %d (limit=%d)",		\
			    extra, atime->field, limit);		\
		atime->field += extra;					\
		if(limit > 0) {						\
			while(limit <= atime->field) {			\
				crm_trace("Overflowing: %d", atime->field); \
				atime->field -= limit;			\
				overflow(atime, 1);			\
			}						\
		}							\
		atime->field = atime->field;				\
		crm_trace("Result: %d", atime->field);		\
	}

#define do_sub_field(atime, field, extra, limit, overflow)		\
	{								\
		crm_trace("Subtracting %d from %d (limit=%d)",	\
			    extra, atime->field, limit);		\
		atime->field -= extra;					\
		while(atime->field < 1) {				\
			crm_trace("Underflowing: %d", atime->field);	\
			atime->field += limit;				\
			overflow(atime, 1);				\
		}							\
		crm_trace("Result: %d", atime->field);		\
	}

#define do_sub_days_field(atime, field, extra, overflow)		\
	{								\
		int __limit = days_per_month(atime->months, atime->years);	\
		crm_trace("Subtracting %d from %d (__limit=%d)",	\
			    extra, atime->field, __limit);		\
		atime->field -= extra;					\
		while(atime->field < 1) {				\
			crm_trace("Underflowing: %d", atime->field);	\
			overflow(atime, 1);				\
			__limit = days_per_month(atime->months, atime->years);	\
			atime->field += __limit;				\
		}							\
		crm_trace("Result: %d", atime->field);		\
	}
#define do_sub_time_field(atime, field, extra, limit, overflow)		\
	{								\
		crm_trace("Subtracting %d from %d (limit=%d)",	\
			    extra, atime->field, limit);		\
		atime->field -= extra;					\
		while(atime->field < 0) {				\
			crm_trace("Underflowing: %d", atime->field);	\
			atime->field += limit;				\
			overflow(atime, 1);				\
		}							\
		crm_trace("Result: %d", atime->field);		\
	}

void
add_seconds(ha_time_t * a_time, int extra)
{
    if (extra < 0) {
        sub_seconds(a_time, -extra);
    } else {
        do_add_time_field(a_time, seconds, extra, 60, add_minutes);
    }
}

void
add_minutes(ha_time_t * a_time, int extra)
{
    if (extra < 0) {
        sub_minutes(a_time, -extra);
    } else {
        do_add_time_field(a_time, minutes, extra, 60, add_hours);
    }
}

void
add_hours(ha_time_t * a_time, int extra)
{
    if (extra < 0) {
        sub_hours(a_time, -extra);
    } else {
        do_add_time_field(a_time, hours, extra, 24, add_days);
    }
}

void
add_days(ha_time_t * a_time, int extra)
{
    if (a_time->has->days == FALSE) {
        crm_trace("has->days == FALSE");
        return;
    }
    if (extra < 0) {
        sub_days(a_time, -extra);
    } else {
        do_add_days_field(a_time, days, extra, add_months);
    }

    convert_from_gregorian(a_time);
}

void
add_weekdays(ha_time_t * a_time, int extra)
{
    if (a_time->has->weekdays == FALSE) {
        crm_trace("has->weekdays == FALSE");
        return;
    }
    if (extra < 0) {
        sub_weekdays(a_time, -extra);
    } else {
        do_add_field(a_time, weekdays, extra, 7, add_weeks);
    }

    convert_from_weekdays(a_time);
}

void
add_yeardays(ha_time_t * a_time, int extra)
{
    if (a_time->has->yeardays == FALSE) {
        crm_trace("has->yeardays == FALSE");
        return;
    }
    if (extra < 0) {
        sub_yeardays(a_time, -extra);
    } else {
        do_add_field(a_time, yeardays, extra,
                     (is_leap_year(a_time->years) ? 366 : 365), add_ordinalyears);
    }

    convert_from_ordinal(a_time);
}

void
add_weeks(ha_time_t * a_time, int extra)
{
    if (a_time->has->weeks == FALSE) {
        crm_trace("has->weeks == FALSE");
        return;
    }
    if (extra < 0) {
        sub_weeks(a_time, -extra);
    } else {
        do_add_field(a_time, weeks, extra, weeks_in_year(a_time->years), add_weekyears);
    }

    convert_from_weekdays(a_time);
}

void
add_months(ha_time_t * a_time, int extra)
{
    int max = 0;

    if (a_time->has->months == FALSE) {
        crm_trace("has->months == FALSE");
        return;
    }
    if (extra < 0) {
        sub_months(a_time, -extra);
    } else {
        do_add_field(a_time, months, extra, 12, add_years);
    }

    max = days_per_month(a_time->months, a_time->years);
    if (a_time->days > max) {
        a_time->days = max;
    }
    convert_from_gregorian(a_time);
}

void
add_years(ha_time_t * a_time, int extra)
{
    if (a_time->has->years == FALSE) {
        crm_trace("has->years == FALSE");
        return;
    }
    a_time->years += extra;
    convert_from_gregorian(a_time);
}

void
add_ordinalyears(ha_time_t * a_time, int extra)
{
    if (a_time->has->years == FALSE) {
        crm_trace("has->years == FALSE");
        return;
    }
    a_time->years += extra;
    convert_from_ordinal(a_time);
}

void
add_weekyears(ha_time_t * a_time, int extra)
{
    if (a_time->has->weekyears == FALSE) {
        crm_trace("has->weekyears == FALSE");
        return;
    }
    a_time->weekyears += extra;
    convert_from_weekdays(a_time);
}

void
sub_seconds(ha_time_t * a_time, int extra)
{
    if (extra < 0) {
        add_seconds(a_time, -extra);
    } else {
        do_sub_time_field(a_time, seconds, extra, 60, sub_minutes);
    }
}

void
sub_minutes(ha_time_t * a_time, int extra)
{
    if (extra < 0) {
        add_minutes(a_time, -extra);
    } else {
        do_sub_time_field(a_time, minutes, extra, 60, sub_hours);
    }
}

void
sub_hours(ha_time_t * a_time, int extra)
{
    if (extra < 0) {
        add_hours(a_time, -extra);
    } else {
        do_sub_time_field(a_time, hours, extra, 24, sub_days);
    }
}

void
sub_days(ha_time_t * a_time, int extra)
{
    if (a_time->has->days == FALSE) {
        crm_trace("has->days == FALSE");
        return;
    }

    crm_trace("Subtracting %d days from %.4d-%.2d-%.2d",
                extra, a_time->years, a_time->months, a_time->days);

    if (extra < 0) {
        add_days(a_time, -extra);
    } else {
        do_sub_days_field(a_time, days, extra, sub_months);
    }

    convert_from_gregorian(a_time);
}

void
sub_weekdays(ha_time_t * a_time, int extra)
{
    if (a_time->has->weekdays == FALSE) {
        crm_trace("has->weekdays == FALSE");
        return;
    }

    crm_trace("Subtracting %d days from %.4d-%.2d-%.2d",
                extra, a_time->years, a_time->months, a_time->days);

    if (extra < 0) {
        add_weekdays(a_time, -extra);
    } else {
        do_sub_field(a_time, weekdays, extra, 7, sub_weeks);
    }

    convert_from_weekdays(a_time);
}

void
sub_yeardays(ha_time_t * a_time, int extra)
{
    if (a_time->has->yeardays == FALSE) {
        crm_trace("has->yeardays == FALSE");
        return;
    }

    crm_trace("Subtracting %d days from %.4d-%.3d", extra, a_time->years, a_time->yeardays);

    if (extra < 0) {
        add_yeardays(a_time, -extra);
    } else {
        do_sub_field(a_time, yeardays, extra,
                     is_leap_year(a_time->years) ? 366 : 365, sub_ordinalyears);
    }

    convert_from_ordinal(a_time);
}

void
sub_weeks(ha_time_t * a_time, int extra)
{
    if (a_time->has->weeks == FALSE) {
        crm_trace("has->weeks == FALSE");
        return;
    }
    if (extra < 0) {
        add_weeks(a_time, -extra);
    } else {
        do_sub_field(a_time, weeks, extra, weeks_in_year(a_time->years), sub_weekyears);
    }

    convert_from_weekdays(a_time);
}

void
sub_months(ha_time_t * a_time, int extra)
{
    if (a_time->has->months == FALSE) {
        crm_trace("has->months == FALSE");
        return;
    }
    if (extra < 0) {
        add_months(a_time, -extra);
    } else {
        do_sub_field(a_time, months, extra, 12, sub_years);
    }
    convert_from_gregorian(a_time);
}

void
sub_years(ha_time_t * a_time, int extra)
{
    if (a_time->has->years == FALSE) {
        crm_trace("has->years == FALSE");
        return;
    }
    a_time->years -= extra;
    convert_from_gregorian(a_time);
}

void
sub_weekyears(ha_time_t * a_time, int extra)
{
    if (a_time->has->weekyears == FALSE) {
        crm_trace("has->weekyears == FALSE");
        return;
    }
    a_time->weekyears -= extra;

    convert_from_weekdays(a_time);
}

void
sub_ordinalyears(ha_time_t * a_time, int extra)
{
    if (a_time->has->years == FALSE) {
        crm_trace("has->years == FALSE");
        return;
    }
    a_time->years -= extra;

    convert_from_ordinal(a_time);
}
