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
#include "libknot/internal/namedb/namedb.h"
#include "libknot/internal/namedb/namedb_trie.h"

#warning handle empty zones

int zone_read_begin(zone_read_t *r, const knot_zonedb_t *db, const knot_dname_t *qname)
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
	zone_contents_find_previous_for_type(zr->zone->contents, owner, type);
}

const zone_node_t *zone_read_closest_encloser(zone_read_t *zr, const knot_dname_t *owner)
{
	zone_contents_find_closest_encloser(zr->zone->contents, owner);
}

int zone_read_rr_iter(zone_rr_iter_t *it, const zone_read_t *zr, const bool sorted)
{
	memset(&it->ch, 0, sizeof(it->ch));
	it->ch.add = zr->zone->contents;
	int ret = changeset_iter_add(&it->it, &it->ch, sorted);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_rrset_init_empty(&it->rr);

	return KNOT_EOK;
}

int zone_read_node_iter(zone_node_iter_t *it, const zone_read_t *zr, const bool sorted, const bool nsec3)
{
	zone_tree_t *t = nsec3 ? zr->zone->contents->nsec3_nodes : zr->zone->contents->nodes;
	if (t == NULL) {
		return KNOT_EINVAL;
	}

	namedb_trie_api()->txn_begin(t, &it->txn, NAMEDB_RDONLY);
	it->it = namedb_trie_api()->iter_begin(&it->txn, sorted ? NAMEDB_SORTED : 0);
	if (it->it == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

const zone_node_t *zone_read_iter_next_node(zone_node_iter_t *it)
{
	if (it && it->it) {
		if (namedb_trie_api()->iter_next(it->it)) {
			namedb_val_t val;
			namedb_trie_api()->iter_val(it->it, &val);
			return val.data;
		}
	}

	return NULL;
}

const knot_rrset_t *zone_read_iter_next_rr(zone_rr_iter_t *it)
{
	it->rr = changeset_iter_next(&it->it);
	return &it->rr;
}

void zone_read_node_iter_clear(zone_node_iter_t *it);

