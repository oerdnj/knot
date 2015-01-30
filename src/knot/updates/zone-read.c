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

#include "knot/updates/zone-read.h"

#warning handle empty zones

int zone_read_begin(zone_read_t *r, const knot_zonedb_t *db, const knot_dname_t *qname)
{
	r->zone = knot_zonedb_find(db, qname);
	int ret = zone_lock_init(&r->lock, LOCK_RCU);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_lock(&r->lock);
	return KNOT_EOK;
}

int zone_read_begin_suffix(zone_read_t *r, knot_zonedb_t *db, const knot_dname_t *qname)
{
	r->zone = knot_zonedb_find_suffix(db, qname);
	int ret = zone_lock_init(&r->lock, LOCK_RCU);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_lock(&r->lock);
	return KNOT_EOK;
}

void zone_read_done(zone_read_t *r)
{
	zone_unlock(&r->lock);
}

const zone_node_t *zone_read_node_for_type(zone_read_t *zr, const knot_dname_t *owner, const uint16_t type)
{
	return zone_contents_find_node_for_type(zr->zone->contents, owner, type);
}

const zone_node_t *zone_read_find_apex(zone_read_t *zr)
{
	return (const zone_node_t *)zr->zone->contents->apex;
}

