/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "knot/zone/adjust.h"

static int adjust_prev_deletion(zone_contents_t *zone, const zone_node_t *n)
{
	
}

static int adjust_prev_addition(zone_contents_t *zone, const zone_node_t *n)
{
	
}

static int adjust_flags(zone_node_t *n)
{
	
}

static int partial_adjust(zone_contents_t *zone, const changeset_t *ch)
{
	return KNOT_EOK;
}

static int full_adjust(zone_contents_t *zone)
{
	return KNOT_EOK;
}

/* ------------------------------- API -------------------------------------- */

int zone_adjust(zone_update_t *up)
{
	if (up->change) {
		return partial_adjust(up->zone, up->change);
	} else {
		return full_adjust(zone);
	}
}
