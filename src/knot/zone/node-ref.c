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
#include "knot/updates/zone-read.h"
#include "knot/dnssec/zone-nsec.h"

enum ref_states {
	REF_VALID = 1 << 0
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

static node_ref_t *fetch_node_ref(zone_node_t *n)
{
	if (n == NULL) {
		return NULL;
	}
	if (n->self_ref == NULL) {
		n->self_ref = node_ref_new((const zone_node_t *)n);
		if (n->self_ref == NULL) {
			return NULL;
		}
	}
	assert(n->self_ref->flags & REF_VALID);

	return n->self_ref;
}

typedef struct zone_node* (*ref_get_t)(zone_read_t *, const knot_dname_t *, const bool);

static zone_node_t *get_prev(zone_read_t *zr, const knot_dname_t *owner, const bool nsec3)
{
	return (zone_node_t *)zone_read_previous_for_type(zr, owner, nsec3 ? KNOT_RRTYPE_NSEC3 : KNOT_RRTYPE_ANY);
}

static zone_node_t *get_parent(zone_read_t *zr, const knot_dname_t *owner, const bool nsec3)
{
	UNUSED(nsec3);
	return (zone_node_t *)zone_read_node_for_type(zr, knot_wire_next_label(owner, NULL), KNOT_RRTYPE_ANY);
}

static zone_node_t *get_nsec3(zone_read_t *zr, const knot_dname_t *owner, const bool nsec3)
{
	UNUSED(nsec3);
	// Get NSEC3PARAM
	const knot_rdataset_t *nsec3param =
		node_rdataset(zone_read_apex(zr), KNOT_RRTYPE_NSEC3PARAM);
	if (nsec3param) {
		// Create NSEC3 hash
		knot_dname_t *nsec3 = knot_create_nsec3_owner(owner, zr->zone->name, nsec3param);
		if (nsec3) {
			const zone_node_t *n = zone_read_node_for_type(zr, nsec3, KNOT_RRTYPE_NSEC3);
			knot_dname_free(&nsec3, NULL);
			return (zone_node_t *)n;
		}
	}

	return NULL;
}

const struct zone_node *node_ref_get(const struct zone_node *n, uint8_t flags, zone_read_t *zone_reader)
{
	node_ref_t **r = NULL;
	uint8_t type = flags & ~REF_NSEC3;
	ref_get_t get_func = NULL;
	switch(type) {
	case REF_PREVIOUS:
		r = &n->prev;
		get_func = get_prev;
	case REF_PARENT:
		r = &n->parent;
		get_func = get_parent;
	case REF_NSEC3:
		r = &n->nsec3_node;
		get_func = get_nsec3;
	default:
		assert(0);
		r = NULL;
	}

	assert(r && get_func);
	if (*r && (*r)->flags & REF_VALID) {
		return (*r)->n;
	} else {
		ref_dec(*r);
		node_ref_t *found_ref = fetch_node_ref(get_func(zone_reader, n->owner, flags & REF_NSEC3));
		ref_inc(found_ref);
		(void)__sync_val_compare_and_swap(r, found_ref, r);
		return found_ref ? found_ref->n : NULL;
	}
}

node_ref_t *node_ref_new(const struct zone_node *n)
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

void node_ref_invalidate(node_ref_t *ref)
{
	(void)__sync_val_compare_and_swap(&ref->flags, ref->flags & ~REF_VALID, &ref->flags);
}

