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

#define FULL_ADJUST_FALLBACK 1

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
		if (node) {
			((zone_node_t *)node)->flags |= NODE_FLAGS_GLUE;
		}
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

static int adjust_node_flags(zone_node_t *n)
{
	if (node_is_deleg(n)) {
		if (n->flags & NODE_FLAGS_NONAUTH || n->flags & NODE_FLAGS_AUTH) {
			return FULL_ADJUST_FALLBACK;
		}
		n->flags &= ~NODE_FLAGS_AUTH;
		n->flags &= ~NODE_FLAGS_NONAUTH;
		n->flags |= NODE_FLAGS_DELEG;
	} else if (node_is_glue(n)) {
		if (n->flags & NODE_FLAGS_DELEG || n->flags & NODE_FLAGS_AUTH) {
			return FULL_ADJUST_FALLBACK;
		}
		n->flags &= ~NODE_FLAGS_DELEG;
		n->flags &= ~NODE_FLAGS_AUTH;
		n->flags |= NODE_FLAGS_NONAUTH;
	} else {
		if (n->flags & NODE_FLAGS_DELEG || n->flags & NODE_FLAGS_NONAUTH) {
			return FULL_ADJUST_FALLBACK;
		}
		n->flags &= ~NODE_FLAGS_DELEG;
		n->flags &= ~NODE_FLAGS_NONAUTH;
		n->flags |= NODE_FLAGS_AUTH;
	}
	
	if (knot_dname_is_wildcard(n->owner) && n->parent) {
		n->parent->flags |= NODE_FLAGS_WILDCARD_CHILD;
	}
	
	return KNOT_EOK;
}

static int adjust_node_flags_full(zone_node_t *n)
{
	if (node_is_deleg(n)) {
		n->flags = NODE_FLAGS_DELEG;
	} else if (node_is_glue(n)) {
		n->flags = NODE_FLAGS_NONAUTH;
	} else {
		n->flags = NODE_FLAGS_AUTH;
	}
	
	if (knot_dname_is_wildcard(n->owner) && n->parent) {
		n->parent->flags |= NODE_FLAGS_WILDCARD_CHILD;
	}
	
	return KNOT_EOK;
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

static int adjust_node_hints(zone_contents_t *zone, zone_node_t *n)
{
	for (uint16_t i = 0; i < n->rrset_count; ++i) {
		if (knot_rrtype_additional_needed(n->rrs[i].type)) {
			int ret = discover_additionals(&n->rrs[i], zone);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}
	
	return KNOT_EOK;
}

static int adjust_node(zone_contents_t *zone,
                       zone_node_t *n)
{
	int ret = adjust_node_flags(n);
	if (ret != KNOT_EOK) {
		return ret;
	}
	
	ret = adjust_node_hints(zone, n);
	if (ret != KNOT_EOK) {
		return ret;
	}
	
	ret = adjust_node_nsec3(zone, n);
	if (ret == KNOT_EOK) {
		return ret;
	}
	
	return KNOT_EOK;
}

static int adjust_node_full(zone_contents_t *zone,
                            zone_node_t *n)
{
	int ret = adjust_node_flags_full(n);
	if (ret != KNOT_EOK) {
		return ret;
	}
	
	ret = adjust_node_hints(zone, n);
	if (ret != KNOT_EOK) {
		return ret;
	}
	
	ret = adjust_node_nsec3(zone, n);
	if (ret == KNOT_EOK) {
		return ret;
	}
	
	return KNOT_EOK;
}

static int adjust_nsec3_node_full(zone_node_t *n)
{
	return adjust_node_flags_full(n);
}

static int adjust_node_deletion(zone_tree_t *t,
                                zone_node_t *n)
{
	zone_node_t *found = NULL;
	zone_tree_get(t, n->owner, &found);
	if (found) {
		int ret = adjust_node_flags(found);
		if (ret != KNOT_EOK) {
			return ret;
		}
		
		// Node stays, no need to fix prev pointers and NSEC3.
		return KNOT_EOK;
	}
	
	if (n->flags & NODE_FLAGS_GLUE) {
		// Deleted glue.
		return FULL_ADJUST_FALLBACK;
	}
	
	zone_node_t *prev = NULL;
	zone_tree_get_less_or_equal(t, n->owner, &found, &prev);
	zone_node_t *next = zone_tree_get_next(t, n->owner);
	assert(prev && next);
	
	next->prev = prev;
	
	return KNOT_EOK;
}

static int adjust_node_addition(zone_tree_t *t, zone_contents_t *zone,
                                zone_node_t *n)
{
	zone_node_t *found = NULL;
	zone_node_t *prev = NULL;
	zone_tree_get_less_or_equal(t, n->owner, &found, &prev);
	
	int ret = adjust_node(zone, found);
	if (ret != KNOT_EOK) {
		return ret;
	}
	
	if (found->flags & NODE_FLAGS_NONAUTH) {
		// Adding glue.
		return FULL_ADJUST_FALLBACK;
	}
	
	prev = zone_tree_get_prev(t, n->owner);
	zone_node_t *next = zone_tree_get_next(t, n->owner);
	assert(prev && next && found);

	found->prev = prev;
	next->prev = found;

	return KNOT_EOK;
}
static bool tree_empty(const zone_contents_t *part)
{
	return hattrie_weight(part->nodes) == 1 && part->apex->rrset_count == 0;
}

// Expects 'n' and 'itt' set.
#define FOR_EACH_NODE(zone, nodes, code, set_prev) \
	if (nodes && !tree_empty(zone)) { \
		hattrie_build_index(nodes); \
		itt = hattrie_iter_begin(nodes, true); \
		if (itt == NULL) { \
			hattrie_iter_free(itt); \
			return KNOT_ENOMEM; \
		} \
		zone_node_t *_prev = NULL; \
		zone_node_t *_first = (zone_node_t *)(*hattrie_iter_val(itt)); \
		while(!hattrie_iter_finished(itt)) { \
			n = (zone_node_t *)(*hattrie_iter_val(itt)); \
			int ret = code; \
			if (ret != KNOT_EOK) { \
				return ret; \
			} \
			if (set_prev && _prev) { \
				n->prev = _prev; \
			} \
			_prev = n; \
			hattrie_iter_next(itt); \
		} \
		hattrie_iter_free(itt); \
		if (set_prev && _first) { \
			_first->prev = _prev; \
		} \
	}

#define WALK_CHANGESET(zone, nodes, code) FOR_EACH_NODE(zone, nodes, code, false)

static int partial_adjust(zone_contents_t *zone, const changeset_t *ch)
{
	hattrie_build_index(zone->nodes);
	
	hattrie_iter_t *itt = NULL;
	zone_node_t *n = NULL;
	WALK_CHANGESET(ch->remove, ch->remove->nodes,
	               adjust_node_deletion(zone->nodes, n));
	WALK_CHANGESET(ch->add, ch->add->nodes,
	               adjust_node_addition(zone->nodes, zone, n));
	
	if (zone->nsec3_nodes) {
		hattrie_build_index(zone->nsec3_nodes);
		WALK_CHANGESET(ch->remove, ch->remove->nsec3_nodes,
		               adjust_node_deletion(zone->nsec3_nodes, n));
		WALK_CHANGESET(ch->add, ch->add->nsec3_nodes,
		               adjust_node_addition(zone->nsec3_nodes, zone, n));
	}
	
	return KNOT_EOK;
}

#define WALK_ZONE_PART(zone, nodes, code) FOR_EACH_NODE(zone, nodes, code, true)

static int full_adjust(zone_contents_t *zone)
{
	hattrie_iter_t *itt = NULL;
	zone_node_t *n = NULL;
	WALK_ZONE_PART(zone, zone->nodes, adjust_node_full(zone, n));
	WALK_ZONE_PART(zone, zone->nsec3_nodes, adjust_nsec3_node_full(n));
	
	return KNOT_EOK;
}

static bool nsec3param_changed(const zone_update_t *up)
{
	return node_rrtype_exists(up->change.add->apex, KNOT_RRTYPE_NSEC3PARAM) ||
	       node_rrtype_exists(up->change.remove->apex, KNOT_RRTYPE_NSEC3PARAM);
}

/* ------------------------------- API -------------------------------------- */

int zone_adjust(zone_update_t *up)
{
	if (!nsec3param_changed(up)) {
		int ret = partial_adjust(up->zone, &up->change);
		if (ret == FULL_ADJUST_FALLBACK) {
			ret = full_adjust(up->zone);
		}
		return ret;
	} else {
		return full_adjust(up->zone);
	}
}

