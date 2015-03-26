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
#include "knot/zone/node-ref.h"
#include "libknot/internal/namedb/namedb.h"
#include "libknot/internal/namedb/namedb_trie.h"

int zone_read_begin(zone_read_t *r, knot_zonedb_t *db, const knot_dname_t *qname)
{
	r->zone = knot_zonedb_find(db, qname);
	int ret = zone_lock_init(&r->lock, ZLOCK_RCU);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_lock(&r->lock);
	return KNOT_EOK;
}

int zone_read_begin_suffix(zone_read_t *r, knot_zonedb_t *db, const knot_dname_t *qname)
{
	r->zone = knot_zonedb_find_suffix(db, qname);
	if (r->zone == NULL) {
		return KNOT_ENOENT;
	}
	int ret = zone_lock_init(&r->lock, ZLOCK_RCU);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_lock(&r->lock);
	return KNOT_EOK;
}

int zone_read_from_zone(zone_read_t *r, zone_t *zone)
{
	r->zone = zone;
	int ret = zone_lock_init(&r->lock, ZLOCK_RCU);
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

const zone_node_t *zone_read_apex(zone_read_t *zr)
{
	return (const zone_node_t *)zr->zone->contents->apex;
}

const zone_node_t *zone_read_previous_for_type(zone_read_t *zr, const knot_dname_t *owner, const uint16_t type)
{
	return zone_contents_find_previous_for_type(zr->zone->contents, owner, type);
}

const zone_node_t *zone_read_closest_encloser(zone_read_t *zr, const knot_dname_t *owner)
{
	return zone_contents_find_closest_encloser(zr->zone->contents, owner);
}

const zone_node_t *zone_read_nsec3_node(zone_read_t *zr, const knot_dname_t *owner)
{
	return zone_contents_find_nsec3(zr->zone->contents, owner);
}

const zone_node_t *zone_read_nsec3_previous(zone_read_t *zr, const knot_dname_t *owner)
{
	return zone_contents_find_nsec3_prev(zr->zone->contents, owner);
}

const zone_node_t *zone_read_find_wildcard_child(zone_read_t *zr, const knot_dname_t *parent)
{
	return zone_contents_find_wildcard_child(zr->zone->contents, parent);
}

bool zone_read_node_is_nonauth(const zone_node_t *node, zone_read_t *zr)
{
	const zone_node_t *parent = node_ref_get(node, REF_PARENT, zr);
	if (parent == NULL) {
		// No parent means we've reached the top of zone hierarchy.
		return false;
	}

	if (node_is_deleg(parent)) {
		return true;
	} else {
		return zone_read_node_is_nonauth(parent, zr);
	}
}

