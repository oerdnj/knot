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

#include "knot/zone/adjust.h"
#include "knot/zone/node-ref.h"
#include "knot/updates/zone-read.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/rrtype/nsec.h"
#include "libknot/rrtype/rdname.h"

static int discover_additionals(struct rr_data *rr_data, zone_read_t *zr)
{
	const knot_rdataset_t *rrs = &rr_data->rrs;

	/* Create new additional nodes. */
	uint16_t rdcount = rrs->rr_count;
	if (rr_data->additional) {
		free(rr_data->additional);
	}
	rr_data->additional = malloc(rdcount * sizeof(zone_node_t *));
	if (rr_data->additional == NULL) {
		return KNOT_ENOMEM;
	}

	for (uint16_t i = 0; i < rdcount; i++) {
		/* Try to find node for the dname in the RDATA. */
		const knot_dname_t *dname = knot_rdata_name(rrs, i, rr_data->type);
		const zone_node_t *node = zone_read_node_for_type(zr, dname, KNOT_RRTYPE_ANY);
		if (node == NULL) {
			// Find closest encloser
			const zone_node_t *encloser = zone_read_closest_encloser(zr, dname);
			if (encloser) {
				node = zone_read_find_wildcard_child(zr, encloser->owner);
			}
		}
		rr_data->additional[i] = node_ref_new((zone_node_t *)node);
		if (rr_data->additional[i] == NULL) {
			return KNOT_ENOMEM;
		}
	}

	return KNOT_EOK;
}

static void adjust_node_references(zone_read_t *zr, zone_node_t *n, bool nsec3)
{
	// Adjusts the references by getting them - the reference will repair itself.
	node_ref_get(n, REF_PARENT, zr);
	if (!nsec3) {
		node_ref_get(n, REF_NSEC3, zr);
	}
	node_ref_get(n, REF_PREVIOUS, zr);
}

static int adjust_node_hints(zone_read_t *zr, zone_node_t *n)
{
	for (uint16_t i = 0; i < n->rrset_count; ++i) {
		if (knot_rrtype_additional_needed(n->rrs[i].type)) {
			int ret = discover_additionals(&n->rrs[i], zr);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

static int adjust_node(zone_read_t *zr, zone_node_t *n, bool nsec3)
{
	adjust_node_references(zr, n, nsec3);
	if (nsec3) {
		return KNOT_EOK;
	}

	return adjust_node_hints(zr, n);
}

static int adjust_node_addition(zone_read_t *zr, zone_node_t *n, bool nsec3)
{
	return adjust_node(zr, n, nsec3);
}

static int adjust_node_deletion(zone_read_t *zr, zone_node_t *n, bool nsec3)
{
	return adjust_node(zr, n, nsec3);
}

static bool tree_empty(const zone_contents_t *part)
{
	return hattrie_weight(part->nodes->db) == 1 && part->apex->rrset_count == 0;
}

// Expects 'n' and 'itt' set.
#define FOR_EACH_NODE(zone, nodes, code) \
	if (nodes && !tree_empty(zone)) { \
		hattrie_build_index(nodes->db); \
		itt = hattrie_iter_begin(nodes->db, true); \
		if (itt == NULL) { \
			hattrie_iter_free(itt); \
			return KNOT_ENOMEM; \
		} \
		while(!hattrie_iter_finished(itt)) { \
			n = (zone_node_t *)(*hattrie_iter_val(itt)); \
			int ret = code; \
			if (ret != KNOT_EOK) { \
				return ret; \
			} \
			hattrie_iter_next(itt); \
		} \
		hattrie_iter_free(itt); \
	}

static int partial_adjust(zone_contents_t *zone, const changeset_t *ch)
{
	// Create zone reader for node reference API compatibility.
	zone_t z = { .contents = zone, .name = zone->apex->owner };
	zone_read_t zr = { .zone = &z };

	hattrie_iter_t *itt = NULL;
	zone_node_t *n = NULL;
	FOR_EACH_NODE(ch->remove, ch->remove->nodes,
	               adjust_node_deletion(&zr, n, false));
	FOR_EACH_NODE(ch->add, ch->add->nodes,
	               adjust_node_addition(&zr, n, false));
	
	if (zone->nsec3_nodes) {
		FOR_EACH_NODE(ch->remove, ch->remove->nsec3_nodes,
		               adjust_node_deletion(&zr, n, true));
		FOR_EACH_NODE(ch->add, ch->add->nsec3_nodes,
		               adjust_node_deletion(&zr, n, true));
	}
	
	return KNOT_EOK;
}

static int full_adjust(zone_contents_t *zone)
{
	// Create zone reader for node reference API compatibility.
	zone_t z = { .contents = zone, .name = zone->apex->owner };
	zone_read_t zr = { .zone = &z };

	hattrie_iter_t *itt = NULL;
	zone_node_t *n = NULL;
	FOR_EACH_NODE(zone, zone->nodes, adjust_node(&zr, n, false));
	FOR_EACH_NODE(zone, zone->nsec3_nodes, adjust_node(&zr, n, true));

	return KNOT_EOK;
}

static int minimal_adjust(zone_contents_t *zone)
{
	// Create zone reader for node reference API compatibility.
	zone_t z = { .contents = zone, .name = zone->apex->owner };
	zone_read_t zr = { .zone = &z };

	hattrie_iter_t *itt = NULL;
	zone_node_t *n = NULL;
	FOR_EACH_NODE(zone, zone->nodes, adjust_node_hints(&zr, n));

	return KNOT_EOK;
}

/* ------------------------------- API -------------------------------------- */

int zone_adjust_full(zone_update_t *up)
{
	return full_adjust(up->new_cont);
}

int zone_adjust_partial(zone_update_t *up)
{
	return partial_adjust(up->zone->contents, &up->change);
}

int zone_adjust_minimal(zone_update_t *up)
{
	return minimal_adjust(up->new_cont);
}

