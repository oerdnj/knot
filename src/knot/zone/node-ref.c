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

#include "knot/zone/node-ref.h"
#include "knot/dnssec/zone-nsec.h"

enum ref_states {
	REF_VALID = 1 << 0,
	REF_DELETED = 1 << 1
};

static void ref_inc(node_ref_t *r)
{
	if (r) {
		__sync_add_and_fetch(&r->count, 1);
	}
}

static void ref_dec(node_ref_t *r)
{
	if (r) {
		assert(r->count > 0);
		const uint32_t ref_count = __sync_sub_and_fetch(&r->count, 1);
		if (ref_count == 0) {
			free(r);
		}
	}
}

static ref_node_t *fetch_node_ref(zone_node_t *n)
{
	if (n == NULL) {
		return NULL;
	}
	if (n->self_ref == NULL) {
		n->self_ref = node_ref_new((const zone_node_t *)n);
		if (found->self_ref == NULL) {
			return NULL;
		}
	}
	assert(n->self_ref & REF_VALID);

	return n->self_ref;
}

static const zone_node_t *get_prev(zone_read_t *zr, const knot_dname_t *owner)
{
#warning zone contents used directly
	return zone_contents_find_previous(zr->zone->contents, owner);
}

static const zone_node_t *get_parent(zone_read_t *zr, const knot_dname_t *owner)
{
	return zone_read_find_node(zr, knot_wire_next_label(owner));
}

static const zone_node_t *get_nsec3(zone_read_t *zr, const knot_dname_t *owner)
{
	// Get NSEC3PARAM
	knot_rdataset_t *nsec3param = node_rdataset(zone_read_get_apex(zr), KNOT_RRTYPE_NSEC3PARAM);
	if (nsec3param) {
		// Create NSEC3 hash
		knot_dname_t *nsec3 = knot_create_nsec3_owner(owner, zr->zone->name, nsec3param);
		if (nsec3) {
			const zone_node_t *n = zone_read_node_for_type(zr, nsec3, KNOT_RRTYPE_NSEC3);
			knot_dname_free(&nsec3, NULL);
			return n;
		}
	} else {
		return NULL;
	}
}

const zone_node_t *node_ref_get(const zone_node_t *n, ref_type_t type, zone_read_t *zr)
{
	node_ref_t **r = NULL;
	(const zone_node_t *)(*get_func)(zone_read_t *, knot_dname_t *) = NULL;
	switch(type) {
	case REF_PREV:
		r = &n->prev;
		get_func = get_prev;
	case REF_PARENT:
		r = &n->parent;
		get_func = get_par;
	case REF_NSEC3:
		r = &n->nsec3_node;
		get_func = get_nsec3;
	default:
		assert(0);
		r = NULL;
	}

	assert(r && get_func);
	if (*r && (*r)->flags & REF_VALID) {
		return r->n;
	} else {
		ref_dec(*r);
		node_ref_t *found_ref = fetch_node_ref(get_func(zr, n->owner));
		ref_inc(found_ref);
		__sync_val_compare_and_swap(*r, found_ref, *r);

		return found_ref ? found_ref->n : NULL;
	}
}

node_ref_t *node_ref_new(const zone_node *n)
{
	node_ref_t *ref = malloc(sizeof(node_ref_t));
	if (ref == NULL) {
		return NULL;
	}

	ref->n = n;
	ref->count = 0;
	ref->flags = REF_VALID;

	return ref;
}

