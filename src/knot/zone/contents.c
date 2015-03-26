/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/zone/contents.h"
#include "knot/common/debug.h"
#include "libknot/internal/macros.h"
#include "libknot/rrset.h"
#include "libknot/internal/base32hex.h"
#include "libknot/descriptor.h"
#include "libknot/internal/trie/hat-trie.h"
#include "libknot/internal/namedb/namedb_trie.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/zone-tree.h"
#include "libknot/packet/wire.h"
#include "libknot/consts.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/rrtype/nsec3.h"
#include "libknot/rrtype/soa.h"
#include "libknot/rrtype/rdname.h"
#include "knot/zone/node-ref.h"
#include "knot/zone/serial.h"
#include "knot/updates/zone-read.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static void node_ref_fix(const zone_contents_t *contents, zone_node_t *n, enum node_ref_type type)
{
	zone_t zone = { .contents = (zone_contents_t *)contents };
	zone_read_t zr = { .zone = &zone };
	node_ref_get(n, type, &zr);
}

/*----------------------------------------------------------------------------*/
static int zone_contents_check_node(const zone_contents_t *contents, const zone_node_t *node)
{
	if (contents == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	if (!knot_dname_is_sub(node->owner, contents->apex->owner)) {
		return KNOT_EOUTOFZONE;
	} else {
		return KNOT_EOK;
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Destroys all RRSets in a node.
 *
 * This function is designed to be used in the tree-iterating functions.
 *
 * \param node Node to destroy RRSets from.
 * \param data Unused parameter.
 */
static int zone_contents_destroy_node_rrsets_from_tree(
	zone_node_t *node, void *data)
{
	UNUSED(data);
	if (node) {
		node_free_rrsets(node, NULL);
		node_free(&node, NULL);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

zone_contents_t *zone_contents_new(const knot_dname_t *apex_name)
{
	if (apex_name == NULL) {
		return NULL;
	}

	zone_contents_t *contents = malloc(sizeof(zone_contents_t));
	if (contents == NULL) {
		return NULL;
	}

	memset(contents, 0, sizeof(zone_contents_t));
	contents->apex = node_new(apex_name, NULL);
	if (contents->apex == NULL) {
		goto cleanup;
	}

	contents->nodes = malloc(sizeof(*(contents->nodes)));
	if (contents->nodes == NULL) {
		goto cleanup;
	}

	int ret = zone_tree_init(contents->nodes, namedb_trie_api(), NULL);
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	ret = zone_tree_insert(contents->nodes, contents->apex);
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	return contents;

cleanup:
	dbg_zone("%s: failure to initialize contents %p\n", __func__, contents);
	free(contents->nodes);
	free(contents->nsec3_nodes);
	free(contents);
	return NULL;
}

/*----------------------------------------------------------------------------*/

static int zone_contents_add_node(zone_contents_t *cont, zone_tree_t *tree, zone_node_t *node)
{
	int ret = zone_contents_check_node(cont, node);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_tree_insert(tree, node);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* No parents for root domain. */
	if (*node->owner == '\0') {
		return KNOT_EOK;
	}

	const uint8_t *parent = knot_wire_next_label(node->owner, NULL);
	zone_node_t *next_node = zone_tree_get(tree, parent);
	while (next_node == NULL) {
		assert(parent);
		/* Create a new node. */
		next_node = node_new(parent, NULL);
		if (next_node == NULL) {
			return KNOT_ENOMEM;
		}

		/* Insert node to a tree. */
		ret = zone_tree_insert(tree, next_node);
		if (ret != KNOT_EOK) {
			node_free(&next_node, NULL);
			return ret;
		}

		node = next_node;
		parent = knot_wire_next_label(parent, NULL);
		next_node = zone_tree_get(tree, parent);
	}

	node_ref_fix(cont, node, REF_PARENT);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int insert_rr(zone_contents_t *z, const knot_rrset_t *rr, bool nsec3)
{
	if (z == NULL || knot_rrset_empty(rr)) {
		return KNOT_EINVAL;
	}

	// check if the RRSet belongs to the zone
	if (!knot_dname_is_sub(rr->owner, z->apex->owner) &&
	    !knot_dname_is_equal(rr->owner, z->apex->owner)) {
		return KNOT_EOUTOFZONE;
	}

	zone_tree_t *t = nsec3 ? z->nsec3_nodes : z->nodes;
	zone_node_t *n = zone_tree_get(t, rr->owner);
	if (n == NULL) {
		// Create new, insert
		n = node_new(rr->owner, NULL);
		if (n == NULL) {
			return KNOT_ENOMEM;
		}
		int ret = zone_contents_add_node(z, t, n);
		if (ret != KNOT_EOK) {
			node_free(&n, NULL);
		}
	}

	return node_add_rrset(n, rr, NULL);
}

static int recreate_normal_tree(const zone_contents_t *z, zone_contents_t *out)
{
	out->nodes->api = (namedb_api_t *)namedb_trie_api();
	out->nodes->db = hattrie_dup(z->nodes->db, NULL);
	if (out->nodes == NULL) {
		return KNOT_ENOMEM;
	}

	// Insert APEX first.
	zone_node_t *apex_cpy = node_shallow_copy(z->apex, NULL);
	if (apex_cpy == NULL) {
		return KNOT_ENOMEM;
	}

	// Normal additions need apex ... so we need to insert directly.
	int ret = zone_tree_insert(out->nodes, apex_cpy);
	if (ret != KNOT_EOK) {
		node_free(&apex_cpy, NULL);
		return ret;
	}

	out->apex = apex_cpy;
	hattrie_iter_t *itt = hattrie_iter_begin(z->nodes->db, true);
	if (itt == NULL) {
		return KNOT_ENOMEM;
	}
	while (!hattrie_iter_finished(itt)) {
		const zone_node_t *to_cpy = (zone_node_t *)*hattrie_iter_val(itt);
		if (to_cpy == z->apex) {
			// Inserted already.
			hattrie_iter_next(itt);
			continue;
		}
		zone_node_t *to_add = node_shallow_copy(to_cpy, NULL);
		if (to_add == NULL) {
			hattrie_iter_free(itt);
			return KNOT_ENOMEM;
		}

		int ret = zone_contents_add_node(out, out->nodes, to_add);
		if (ret != KNOT_EOK) {
			node_free(&to_add, NULL);
			hattrie_iter_free(itt);
			return ret;
		}
		hattrie_iter_next(itt);
	}

	hattrie_iter_free(itt);
	hattrie_build_index(out->nodes->db);

	return KNOT_EOK;
}

static int recreate_nsec3_tree(const zone_contents_t *z, zone_contents_t *out)
{
	out->nsec3_nodes->api = (namedb_api_t *)namedb_trie_api();
	out->nsec3_nodes->db = hattrie_dup(z->nsec3_nodes->db, NULL);
	if (out->nsec3_nodes == NULL) {
		return KNOT_ENOMEM;
	}

	hattrie_iter_t *itt = hattrie_iter_begin(z->nsec3_nodes->db, false);
	if (itt == NULL) {
		return KNOT_ENOMEM;
	}
	while (!hattrie_iter_finished(itt)) {
		const zone_node_t *to_cpy = (zone_node_t *)*hattrie_iter_val(itt);
		zone_node_t *to_add = node_shallow_copy(to_cpy, NULL);
		if (to_add == NULL) {
			hattrie_iter_free(itt);
			return KNOT_ENOMEM;
		}
		int ret = zone_contents_add_node(out, out->nsec3_nodes, to_add);
		if (ret != KNOT_EOK) {
			hattrie_iter_free(itt);
			node_free(&to_add, NULL);
			return ret;
		}
		hattrie_iter_next(itt);
	}

	hattrie_iter_free(itt);
	hattrie_build_index(out->nsec3_nodes->db);

	return KNOT_EOK;
}

bool zone_contents_rrset_is_nsec3rel(const knot_rrset_t *rr)
{
	if (rr == NULL) {
		return false;
	}

	if (rr->type == KNOT_RRTYPE_NSEC3) {
		return true;
	}

	if (rr->type != KNOT_RRTYPE_RRSIG) {
		return false;
	}

	if (rr->rrs.rr_count == 0) {
		// Not enough data are present, go with non-NSEC3.
		return false;
	}

	return knot_rrsig_type_covered(&rr->rrs, 0) == KNOT_RRTYPE_NSEC3;
}

int zone_contents_add_rr(zone_contents_t *z, const knot_rrset_t *rr)
{
	if (z == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	return insert_rr(z, rr, zone_contents_rrset_is_nsec3rel(rr));
}

/*----------------------------------------------------------------------------*/

const zone_node_t *zone_contents_find_previous_for_type(const zone_contents_t *zone,
                                                        const knot_dname_t *name, uint16_t type)
{
	zone_tree_t *t = type == KNOT_RRTYPE_NSEC3 ? zone->nsec3_nodes : zone->nodes;
	if (t) {
		const zone_node_t *prev = zone_tree_get_prev(t, name);
		zone_t fake_zone = { .contents = (zone_contents_t *)zone, .name = zone->apex->owner };
		zone_read_t fake_zr = { .zone = &fake_zone };
		if (zone_read_node_is_nonauth(prev, &fake_zr)) {
			// We only care about authoritative nodes, there must be at least one.
			return zone_contents_find_previous_for_type(zone, prev->owner, type);
		}
		return prev;
	} else {
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/

zone_node_t *zone_contents_find_wildcard_child(const zone_contents_t *contents,
                                               const knot_dname_t *parent)
{
	if (contents == NULL || parent == NULL) {
		return NULL;
	}

	knot_dname_t wildcard[KNOT_DNAME_MAXLEN] = { 0x01, '*' };
	knot_dname_to_wire(wildcard + 2, parent, KNOT_DNAME_MAXLEN - 2);
	return zone_tree_get(contents->nodes, wildcard);
}

zone_node_t *zone_contents_find_closest_encloser(const zone_contents_t *zone, const knot_dname_t *owner)
{
	const knot_dname_t *cut = knot_wire_next_label(owner, NULL);
	while (knot_dname_size(cut) > 1) {
		zone_node_t *n = zone_tree_get(zone->nodes, cut);
		if (n) {
			return n;
		}
		cut = knot_wire_next_label(cut, NULL);
	}

	return NULL;
}

static zone_node_t *do_nsec3_op(const zone_contents_t *zone, const knot_dname_t *owner,
                                zone_node_t *(*op)(zone_tree_t *, const knot_dname_t *))
{
	if (zone == NULL || owner == NULL || op == NULL) {
		return NULL;
	}

	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		return NULL;
	}

	const knot_rdataset_t *nsec3param =
		node_rdataset(zone->apex, KNOT_RRTYPE_NSEC3PARAM);
	if (nsec3param == NULL) {
		return NULL;
	}
	
	knot_dname_t *nsec3_name = knot_create_nsec3_owner(owner, zone->apex->owner, NULL);
	if (nsec3_name == NULL) {
		return NULL;
	}
	
	zone_node_t *node = op(zone->nsec3_nodes, nsec3_name);
	knot_dname_free(&nsec3_name, NULL);
	return node;
}

zone_node_t *zone_contents_find_nsec3(const zone_contents_t *zone, const knot_dname_t *owner)
{
	return do_nsec3_op(zone, owner, zone_tree_get);
}

zone_node_t *zone_contents_find_nsec3_prev(const zone_contents_t *zone, const knot_dname_t *owner)
{
	return do_nsec3_op(zone, owner, zone_tree_get_prev);
}

/*----------------------------------------------------------------------------*/

int zone_contents_shallow_copy(const zone_contents_t *from, zone_contents_t **to)
{
	if (from == NULL || to == NULL) {
		return KNOT_EINVAL;
	}

	/* Copy to same destination as source. */
	if (from == *to) {
		return KNOT_EINVAL;
	}

	zone_contents_t *contents = calloc(1, sizeof(zone_contents_t));
	if (contents == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = recreate_normal_tree(from, contents);
	if (ret != KNOT_EOK) {
		zone_tree_clear(contents->nodes);
		free(contents->nodes);
		return ret;
	}

	if (from->nsec3_nodes) {
		ret = recreate_nsec3_tree(from, contents);
		if (ret != KNOT_EOK) {
			zone_tree_clear(contents->nodes);
			free(contents->nodes);
			zone_tree_clear(contents->nsec3_nodes);
			free(contents->nsec3_nodes);
			return ret;
		}
	} else {
		contents->nsec3_nodes = NULL;
	}

	*to = contents;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void zone_contents_free(zone_contents_t **contents)
{
	if (contents == NULL || *contents == NULL) {
		return;
	}

	zone_tree_clear((*contents)->nodes);
	free((*contents)->nodes);
	zone_tree_clear((*contents)->nsec3_nodes);
	free((*contents)->nsec3_nodes);

	free(*contents);
	*contents = NULL;
}

/*----------------------------------------------------------------------------*/

void zone_contents_deep_free(zone_contents_t **contents)
{
	if (contents == NULL || *contents == NULL) {
		return;
	}

	if ((*contents) != NULL) {
		// Delete NSEC3 tree
		zone_tree_apply(
			(*contents)->nsec3_nodes,
			zone_contents_destroy_node_rrsets_from_tree, NULL, false);

		// Delete normal tree
		zone_tree_apply(
			(*contents)->nodes,
			zone_contents_destroy_node_rrsets_from_tree, NULL, false);
	}

	zone_contents_free(contents);
}

/*----------------------------------------------------------------------------*/

const knot_rdataset_t *zone_contents_soa(const zone_contents_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return node_rdataset(zone->apex, KNOT_RRTYPE_SOA);
}

uint32_t zone_contents_serial(const zone_contents_t *zone)
{
	const knot_rdataset_t *soa = zone_contents_soa(zone);
	if (soa == NULL) {
		return 0;
	}

	return knot_soa_serial(soa);
}

uint32_t zone_contents_next_serial(const zone_contents_t *zone, int policy)
{
	assert(zone);

	uint32_t old_serial = zone_contents_serial(zone);
	uint32_t new_serial = 0;

	switch (policy) {
	case CONF_SERIAL_INCREMENT:
		new_serial = (uint32_t)old_serial + 1;
		break;
	case CONF_SERIAL_UNIXTIME:
		new_serial = (uint32_t)time(NULL);
		break;
	default:
		assert(0);
	}

	/* If the new serial is 'lower' or equal than the new one, warn the user.*/
	if (serial_compare(old_serial, new_serial) >= 0) {
		log_zone_warning(zone->apex->owner, "updated serial is lower "
		                 "than current, serial %u -> %u",
		                 old_serial, new_serial);
	}

	return new_serial;
}

bool zone_contents_is_signed(const zone_contents_t *zone)
{
	return node_rrtype_is_signed(zone->apex, KNOT_RRTYPE_SOA);
}

bool zone_contents_is_empty(const zone_contents_t *zone)
{
	return !zone || !node_rrtype_exists(zone->apex, KNOT_RRTYPE_SOA);
}

zone_node_t *zone_contents_get_node_for_rr(const zone_contents_t *zone, const knot_rrset_t *rrset)
{
	if (zone == NULL || rrset == NULL) {
		return NULL;
	}

	const bool nsec3 = zone_contents_rrset_is_nsec3rel(rrset);
	zone_tree_t *t = nsec3 ? zone->nsec3_nodes : zone->nodes;
	if (t == NULL) {
		return NULL;
	}
	zone_node_t *node = zone_tree_get(t, rrset->owner);
	if (node == NULL) {
		node = node_new(rrset->owner, NULL);
		if (node == NULL) {
			return NULL;
		}
		int ret = zone_tree_insert(t, node);
		if (ret != KNOT_EOK) {
			node_free(&node, NULL);
			return NULL;
		}
	}

	return node;
}

zone_node_t *zone_contents_find_node_for_rr(const zone_contents_t *zone, const knot_rrset_t *rrset)
{
	if (zone == NULL || rrset == NULL) {
		return NULL;
	}

	const bool nsec3 = zone_contents_rrset_is_nsec3rel(rrset);
	zone_tree_t *t = nsec3 ? zone->nodes : zone->nsec3_nodes;
	if (t) {
		return zone_tree_get(t, rrset->owner);
	} else {
		return NULL;
	}
}

zone_node_t *zone_contents_greatest_child(const zone_contents_t *zone, const knot_dname_t *parent)
{
	if (knot_dname_size(parent) + 2 > KNOT_DNAME_MAXLEN) {
		// Not enough space for children.
		return false;
	}

	knot_dname_t dn[KNOT_DNAME_MAXLEN] = { 0x01, 0xff };
	knot_dname_to_wire(dn + 2, parent, KNOT_DNAME_MAXLEN);
	zone_node_t *child = zone_tree_get(zone->nodes, dn);
	if (child) {
		return child;
	}

	child = zone_tree_get_prev(zone->nodes, dn);
	assert(child);
	const int parent_labels = knot_dname_labels(parent, NULL);
	const int child_labels = knot_dname_labels(child->owner, NULL);
	if (child_labels <= parent_labels) {
		return NULL;
	}

	if (knot_dname_matched_labels(parent, child->owner) != parent_labels) {
		return NULL;
	}

	return child;
}

bool zone_contents_has_children(const zone_contents_t *zone, const knot_dname_t *owner)
{
	return zone_contents_greatest_child(zone, owner) != NULL;
}

zone_node_t *zone_contents_find_node_for_type(const zone_contents_t *zone, const knot_dname_t *owner, const uint16_t type)
{
	knot_rrset_t rr = { .owner = (knot_dname_t *)owner, .type = type };
	return zone_contents_get_node_for_rr(zone, &rr);
}

void zone_contents_delete_empty_node(zone_contents_t *zone, zone_tree_t *tree, zone_node_t *node)
{
	assert(zone);
	assert(tree);
	assert(node);
	if (node->rrset_count == 0 && !zone_contents_has_children(zone, node->owner)) {
		const knot_dname_t *parent_dname = knot_wire_next_label(node->owner, NULL);
		zone_node_t *parent_node = NULL;
		if (tree == zone->nsec3_nodes) {
			// Only one level in NSEC3 tree
			parent_node = (node == zone->apex) ? NULL : zone->apex;
		} else {
			parent_node = zone_contents_find_node_for_type(zone,
			                                               parent_dname,
			                                               KNOT_RRTYPE_ANY);
		}
		if (parent_node && parent_node != zone->apex) {
			// Recurse using the parent node, do not delete possibly empty parent.
			zone_contents_delete_empty_node(zone, tree, parent_node);
		}

		// Delete node
		zone_node_t *removed_node = NULL;
		zone_tree_remove(tree, node->owner, &removed_node);
		UNUSED(removed_node);
		node_free(&node, NULL);
	}
}

