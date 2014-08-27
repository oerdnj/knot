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

#include <assert.h>

#include "common-knot/hattrie/hat-trie.h"
#include "knot/zone/adjust.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/rrtype/nsec.h"
#include "libknot/rrtype/rdname.h"

typedef void (*adjust_callback_t)(zone_tree_t *, zone_contents_t *, zone_node_t *);

static int discover_additionals(struct rr_data *rr_data,
                                struct zone_contents_t *zone)
{
	const knot_rdataset_t *rrs = &rr_data->rrs;

	// Create new additional nodes.
	const uint16_t rdcount = rrs->rr_count;
	if (rr_data->additional) {
		free(rr_data->additional);
	}
	rr_data->additional = malloc(rdcount * sizeof(zone_node_t *));
	if (rr_data->additional == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	for (uint16_t i = 0; i < rdcount; i++) {
		// Try to find node for the dname in the RDATA
		const knot_dname_t *dname = knot_rdata_name(rrs, i, rr_data->type);
		const zone_node_t *node = NULL, *encloser = NULL, *prev = NULL;
		
		zone_contents_find_dname(zone, dname, &node, &encloser, &prev);
		if (node == NULL && encloser) {
			// Try to find wildcard child in the zone.
			node = zone_contents_find_wildcard_child(zone,
			                                         encloser);
		}

		rr_data->additional[i] = (zone_node_t *)node;
	}

	return KNOT_EOK;
}

static bool node_is_deleg(const zone_node_t *n)
{
	return node_rrtype_exists(n, KNOT_RRTYPE_NS) &&
	       !node_rrtype_exists(n, KNOT_RRTYPE_SOA);
}

static bool node_is_glue(const zone_node_t *n)
{
	/*
	 * Go up in the tree and look for delegation points. If we reach the
	 * top without seeing delegation point (parent is NULL), then
	 * node is authoritative.
	 */
	return n->parent && (node_is_deleg(n->parent) || node_is_glue(n->parent));
}

#warning TODO: purge flags, use function like those above instead
static void adjust_node_flags(zone_node_t *n)
{
	if (node_is_deleg(n)) {
		n->flags &= ~NODE_FLAGS_AUTH;
		n->flags &= ~NODE_FLAGS_NONAUTH;
		n->flags |= NODE_FLAGS_DELEG;
	} else if (node_is_glue(n)) {
		n->flags &= ~NODE_FLAGS_DELEG;
		n->flags &= ~NODE_FLAGS_AUTH;
		n->flags |= NODE_FLAGS_NONAUTH;
	} else {
		n->flags &= ~NODE_FLAGS_DELEG;
		n->flags &= ~NODE_FLAGS_NONAUTH;
		n->flags |= NODE_FLAGS_AUTH;
	}
	
	if (knot_dname_is_wildcard(n->owner) && n->parent) {
		n->parent->flags |= NODE_FLAGS_WILDCARD_CHILD;
	}
}

static int adjust_node_nsec3(zone_contents_t *zone, zone_node_t *n)
{
	if (zone->nsec3_nodes && !node_rrtype_exists(n, KNOT_RRTYPE_NSEC3)) {
		knot_dname_t *hash =
			knot_create_nsec3_owner(n->owner,
			                        zone->apex->owner,
			                        node_rdataset(zone->apex,
			                                      KNOT_RRTYPE_NSEC3PARAM));
		if (hash == NULL) {
			return KNOT_ERROR;
		}
		
		knot_dname_to_lower(hash);
		zone_tree_get(zone->nsec3_nodes, hash, &n->nsec3_node);
		if (n->nsec3_node) {
			// Set backward pointer (NSEC3 -> normal)
			n->nsec3_node->nsec3_node = n;
		}
		knot_dname_free(&hash, NULL);
	}
	
	return KNOT_EOK;
}

static void adjust_node_hints(zone_contents_t *zone, zone_node_t *n)
{
	for (uint16_t i = 0; i < n->rrset_count; ++i) {
		if (knot_rrtype_additional_needed(n->rrs[i].type)) {
			discover_additionals(&n->rrs[i], zone);
		}
	}
}

static void adjust_node_full(zone_tree_t *t, zone_contents_t *zone,
                             zone_node_t *n)
{
	UNUSED(t);
	adjust_node_flags(n);
	adjust_node_nsec3(zone, n);
	adjust_node_hints(zone, n);
}

static void adjust_nsec3_node_full(zone_tree_t *t, zone_contents_t *zone,
                                   zone_node_t *n)
{
	UNUSED(t);
	UNUSED(zone);
	adjust_node_flags(n);
}

static void adjust_node_deletion(zone_tree_t *t, zone_contents_t *zone,
                                 zone_node_t *n)
{
	UNUSED(zone);
	zone_node_t *found = NULL;
	zone_tree_get(t, n->owner, &found);
	if (found) {
		adjust_node_flags(found);
		adjust_node_hints(zone, n);
		// Node stays, no need to fix prev pointers and NSEC3.
		return;
	}
	
	zone_node_t *prev = NULL;
	zone_tree_get_less_or_equal(t, n->owner, &found, &prev);
	zone_node_t *next = zone_tree_get_next(t, n->owner);
	assert(prev && next);
	
	next->prev = prev;
}

static void adjust_node_addition(zone_tree_t *t, zone_contents_t *zone,
                                 zone_node_t *n)
{
	adjust_node_full(t, zone, n);
	
	zone_node_t *found = NULL;
	zone_node_t *prev = NULL;
	zone_tree_get_less_or_equal(t, n->owner, &found, &prev);
	prev = zone_tree_get_prev(t, n->owner);
	zone_node_t *next = zone_tree_get_next(t, n->owner);
	assert(prev && next && found);
	assert(knot_dname_is_equal(found->owner, n->owner));

	found->prev = prev;
	next->prev = found;
}

static bool set_prev(adjust_callback_t cb)
{
	return cb == adjust_node_full || cb == adjust_nsec3_node_full;
}

static int apply_to_tree(zone_contents_t *zone,
                         zone_tree_t *t_walk, zone_tree_t *t_find,
                         adjust_callback_t cb, bool sort)
{
	hattrie_iter_t *itt = hattrie_iter_begin(t_walk, sort);
	if (itt == NULL) {
		return KNOT_ERROR;
	}

	zone_node_t *first = (zone_node_t *)(*hattrie_iter_val(itt));
	zone_node_t *curr = NULL;
	zone_node_t *prev = NULL;
	while(!hattrie_iter_finished(itt)) {
		curr = (zone_node_t *)(*hattrie_iter_val(itt));
		cb(t_find, zone, curr);
		if (set_prev(cb) && prev) {
			curr->prev = prev;
		}
		prev = curr;
		hattrie_iter_next(itt);
	}
	
	if (set_prev(cb)) {
		// Connect first to last.
		assert(first && prev);
		first->prev = prev;
	}
	hattrie_iter_free(itt);
	
	return KNOT_EOK;
}

static bool tree_empty(const zone_contents_t *part)
{
	return hattrie_weight(part->nodes) == 1 && part->apex->rrset_count == 0;
}

static int apply_to_part(const zone_contents_t *part, zone_contents_t *zone,
                         adjust_callback_t cb)
{
	int ret = KNOT_EOK;
	if (!tree_empty(part)) {
		ret = apply_to_tree(zone, part->nodes, zone->nodes, cb, false);
	}
	
	if (part->nsec3_nodes && zone->nsec3_nodes && ret == KNOT_EOK) {
		// Only apply for NSEC3 nodes when there are some left.
		ret = apply_to_tree(zone, part->nsec3_nodes, zone->nsec3_nodes,
		                    cb, false);
	}
	
	return ret;
}

static int partial_adjust(zone_contents_t *zone, const changeset_t *ch)
{
	int ret = apply_to_part(ch->remove, zone, adjust_node_deletion);
	if (ret == KNOT_EOK) {
		ret = apply_to_part(ch->add, zone, adjust_node_addition);
	}
	
	return ret;
}

static int full_adjust(zone_contents_t *zone)
{
	int ret = apply_to_tree(zone, zone->nodes, NULL, adjust_node_full, true);
	if (ret == KNOT_EOK && zone->nsec3_nodes) {
		ret = apply_to_tree(zone, zone->nsec3_nodes, NULL, adjust_nsec3_node_full, true);
	}
	
	return ret;
}

static bool nsec3param_changed(const zone_update_t *up)
{
	return node_rrtype_exists(up->change->add->apex, KNOT_RRTYPE_NSEC3PARAM) ||
	       node_rrtype_exists(up->change->remove->apex, KNOT_RRTYPE_NSEC3PARAM);
}

/* ------------------------------- API -------------------------------------- */

int zone_adjust(zone_update_t *up)
{
	// Build indices for lookup and sorted walk.
	hattrie_build_index(up->zone->nodes);
	if (up->zone->nsec3_nodes) {
		hattrie_build_index(up->zone->nsec3_nodes);
	}
	
	if (up->change && !nsec3param_changed(up)) {
		printf("partial\n");
		return partial_adjust(up->zone, up->change);
	} else {
		printf("full\n");
		return full_adjust(up->zone);
	}
}

