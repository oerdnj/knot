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
#include "common/debug.h"
#include "libknot/rrset.h"
#include "common/base32hex.h"
#include "libknot/descriptor.h"
#include "common-knot/hattrie/hat-trie.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/zone-tree.h"
#include "libknot/packet/wire.h"
#include "libknot/consts.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/rrtype/nsec3.h"
#include "libknot/rrtype/soa.h"
#include "libknot/rrtype/rdname.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

typedef struct {
	zone_contents_apply_cb_t func;
	void *data;
} zone_tree_func_t;

/*----------------------------------------------------------------------------*/

static int tree_apply_cb(zone_node_t **node, void *data)
{
	if (node == NULL || data == NULL) {
		return KNOT_EINVAL;
	}

	zone_tree_func_t *f = (zone_tree_func_t *)data;
	return f->func(*node, f->data);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if the given node can be inserted into the given zone.
 *
 * Checks if both the arguments are non-NULL and if the owner of the node
 * belongs to the zone (i.e. is a subdomain of the zone apex).
 *
 * \param zone Zone to which the node is going to be inserted.
 * \param node Node to check.
 *
 * \retval KNOT_EOK if both arguments are non-NULL and the node belongs to the
 *         zone.
 * \retval KNOT_EINVAL if either of the arguments is NULL.
 * \retval KNOT_EOUTOFZONE if the node does not belong to the zone.
 */
static int zone_contents_check_node(
	const zone_contents_t *contents, const zone_node_t *node)
{
	if (contents == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	// assert or just check??
	assert(contents->apex != NULL);

	if (!knot_dname_is_sub(node->owner,
				       contents->apex->owner)) {
		return KNOT_EOUTOFZONE;
	}
	return KNOT_EOK;
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
	zone_node_t **tnode, void *data)
{
	UNUSED(data);
	assert(tnode != NULL);
	if (*tnode != NULL) {
		node_free_rrsets(*tnode, NULL);
		node_free(tnode, NULL);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

/*!
 * \brief Tries to find the given domain name in the zone tree.
 *
 * \param zone Zone to search in.
 * \param name Domain name to find.
 * \param node Found node.
 * \param previous Previous node in canonical order (i.e. the one directly
 *                 preceding \a name in canonical order, regardless if the name
 *                 is in the zone or not).
 *
 * \retval <> 0 if the domain name was found. In such case \a node holds the
 *              zone node with \a name as its owner. \a previous is set
 *              properly.
 * \retval 0 if the domain name was not found. \a node may hold any (or none)
 *           node. \a previous is set properly.
 */
static int zone_contents_find_in_tree(zone_tree_t *tree,
                                           const knot_dname_t *name,
                                           zone_node_t **node,
                                           zone_node_t **previous)
{
	assert(tree != NULL);
	assert(name != NULL);
	assert(node != NULL);
	assert(previous != NULL);

	zone_node_t *found = NULL, *prev = NULL;

	int exact_match = zone_tree_get_less_or_equal(tree, name, &found,
							   &prev);

	assert(exact_match >= 0);
	*node = found;
	*previous = prev;

	return exact_match;
}

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

zone_contents_t *zone_contents_new(const knot_dname_t *apex_name)
{
	dbg_zone("%s(%p)\n", __func__, apex_name);
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

	contents->nodes = zone_tree_create();
	if (contents->nodes == NULL) {
		goto cleanup;
	}

	if (zone_tree_insert(contents->nodes, contents->apex) != KNOT_EOK) {
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

static zone_node_t *zone_contents_get_node(const zone_contents_t *zone,
                                           const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	zone_node_t *n;
	int ret = zone_tree_get(zone->nodes, name, &n);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to find name in the zone tree.\n");
		return NULL;
	}

	return n;
}

/*----------------------------------------------------------------------------*/

static int zone_contents_add_node(zone_contents_t *zone, zone_node_t *node,
                                  bool create_parents)
{
	if (zone == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	int ret = 0;
	if ((ret = zone_contents_check_node(zone, node)) != 0) {
		dbg_zone("Node check failed.\n");
		return ret;
	}

	ret = zone_tree_insert(zone->nodes, node);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to insert node into zone tree.\n");
		return ret;
	}

	if (!create_parents) {
		return KNOT_EOK;
	}

	dbg_zone_detail("Creating parents of the node.\n");

	/* No parents for root domain. */
	if (*node->owner == '\0')
		return KNOT_EOK;

	zone_node_t *next_node = NULL;
	const uint8_t *parent = knot_wire_next_label(node->owner, NULL);

	if (knot_dname_cmp(zone->apex->owner, parent) == 0) {
		dbg_zone_detail("Zone apex is the parent.\n");
		node_set_parent(node, zone->apex);

		// check if the node is not wildcard child of the parent
		if (knot_dname_is_wildcard(node->owner)) {
			zone->apex->flags |= NODE_FLAGS_WILDCARD_CHILD;
		}
	} else {
		while (parent != NULL &&
		       !(next_node = zone_contents_get_node(zone, parent))) {

			/* Create a new node. */
			dbg_zone_detail("Creating new node.\n");
			next_node = node_new(parent, NULL);
			if (next_node == NULL) {
				return KNOT_ENOMEM;
			}

			/* Insert node to a tree. */
			dbg_zone_detail("Inserting new node to zone tree.\n");
			ret = zone_tree_insert(zone->nodes, next_node);
			if (ret != KNOT_EOK) {
				node_free(&next_node, NULL);
				return ret;
			}

			/* Update node pointers. */
			node_set_parent(node, next_node);
			if (knot_dname_is_wildcard(node->owner)) {
				next_node->flags |= NODE_FLAGS_WILDCARD_CHILD;
			}

			dbg_zone_detail("Next parent.\n");
			node = next_node;
			parent = knot_wire_next_label(parent, NULL);
		}

		// set the found parent (in the zone) as the parent of the last
		// inserted node
		assert(node->parent == NULL);
		node_set_parent(node, next_node);

		dbg_zone_detail("Created all parents.\n");
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int zone_contents_add_nsec3_node(zone_contents_t *zone, zone_node_t *node)
{
	if (zone == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	int ret = 0;
	if ((ret = zone_contents_check_node(zone, node)) != 0) {
		dbg_zone("Failed node check: %s\n", knot_strerror(ret));
		return ret;
	}

	/* Create NSEC3 tree if not exists. */
	if (zone->nsec3_nodes == NULL) {
		zone->nsec3_nodes = zone_tree_create();
		if (zone->nsec3_nodes == NULL) {
			return KNOT_ENOMEM;
		}
	}

	// how to know if this is successfull??
	ret = zone_tree_insert(zone->nsec3_nodes, node);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to insert node into NSEC3 tree: %s.\n",
			 knot_strerror(ret));
		return ret;
	}

	// no parents to be created, the only parent is the zone apex
	// set the apex as the parent of the node
	node_set_parent(node, zone->apex);

	// cannot be wildcard child, so nothing to be done

	return KNOT_EOK;
}

static zone_node_t *zone_contents_get_nsec3_node(const zone_contents_t *zone,
                                                 const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	zone_node_t *n;
	int ret = zone_tree_get(zone->nsec3_nodes, name, &n);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to find NSEC3 name in the zone tree."
				  "\n");
		return NULL;
	}

	return n;
}

static int insert_rr(zone_contents_t *z,
                     const knot_rrset_t *rr, zone_node_t **n,
                     bool nsec3)
{
	if (z == NULL || knot_rrset_empty(rr) || n == NULL) {
		return KNOT_EINVAL;
	}

	// check if the RRSet belongs to the zone
	if (!knot_dname_is_sub(rr->owner, z->apex->owner) &&
	    !knot_dname_is_equal(rr->owner, z->apex->owner)) {
		return KNOT_EOUTOFZONE;
	}

	int ret = KNOT_EOK;
	if (*n == NULL) {
		*n = nsec3 ? zone_contents_get_nsec3_node(z, rr->owner) :
		             zone_contents_get_node(z, rr->owner);
		if (*n == NULL) {
			// Create new, insert
			*n = node_new(rr->owner, NULL);
			if (*n == NULL) {
				return KNOT_ENOMEM;
			}
			ret = nsec3 ? zone_contents_add_nsec3_node(z, *n) :
			              zone_contents_add_node(z, *n, true);
			if (ret != KNOT_EOK) {
				node_free(n, NULL);
			}
		}
	}

	return node_add_rrset(*n, rr, NULL);
}

static int recreate_normal_tree(const zone_contents_t *z, zone_contents_t *out)
{
	out->nodes = hattrie_dup(z->nodes, NULL);
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

	hattrie_iter_t *itt = hattrie_iter_begin(z->nodes, true);
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

		int ret = zone_contents_add_node(out, to_add, true);
		if (ret != KNOT_EOK) {
			node_free(&to_add, NULL);
			hattrie_iter_free(itt);
			return ret;
		}
		hattrie_iter_next(itt);
	}

	hattrie_iter_free(itt);
	hattrie_build_index(out->nodes);

	return KNOT_EOK;
}

static int recreate_nsec3_tree(const zone_contents_t *z, zone_contents_t *out)
{
	out->nsec3_nodes = hattrie_dup(z->nsec3_nodes, NULL);
	if (out->nsec3_nodes == NULL) {
		return KNOT_ENOMEM;
	}

	hattrie_iter_t *itt = hattrie_iter_begin(z->nsec3_nodes, false);
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
		int ret = zone_contents_add_nsec3_node(out, to_add);
		if (ret != KNOT_EOK) {
			hattrie_iter_free(itt);
			node_free(&to_add, NULL);
			return ret;
		}
		hattrie_iter_next(itt);
	}

	hattrie_iter_free(itt);
	hattrie_build_index(out->nsec3_nodes);

	return KNOT_EOK;
}

static bool rrset_is_nsec3rel(const knot_rrset_t *rr)
{
	if (rr == NULL) {
		return false;
	}

	/* Is NSEC3 or non-empty RRSIG covering NSEC3. */
	return ((rr->type == KNOT_RRTYPE_NSEC3)
	        || (rr->type == KNOT_RRTYPE_RRSIG
	            && knot_rrsig_type_covered(&rr->rrs, 0)
	            == KNOT_RRTYPE_NSEC3));
}

int zone_contents_add_rr(zone_contents_t *z, const knot_rrset_t *rr,
                         zone_node_t **n)
{
	return insert_rr(z, rr, n, rrset_is_nsec3rel(rr));
}

/*----------------------------------------------------------------------------*/

const zone_node_t *zone_contents_find_node(const zone_contents_t *zone,
                                           const knot_dname_t *name)
{
	return zone_contents_get_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int zone_contents_find_dname(const zone_contents_t *zone,
                             const knot_dname_t *name,
                             const zone_node_t **node,
                             const zone_node_t **closest_encloser,
                             const zone_node_t **previous)
{
	if (zone == NULL || name == NULL || node == NULL
	    || closest_encloser == NULL || previous == NULL
	    || zone->apex == NULL || zone->apex->owner == NULL) {
		return KNOT_EINVAL;
	}

dbg_zone_exec_verb(
	char *name_str = knot_dname_to_str(name);
	char *zone_str = knot_dname_to_str(zone->apex->owner);
	dbg_zone_verb("Searching for name %s in zone %s...\n",
		      name_str, zone_str);
	free(name_str);
	free(zone_str);
);

	zone_node_t *found = NULL, *prev = NULL;

	int exact_match = zone_contents_find_in_tree(zone->nodes, name,
							    &found, &prev);
	assert(exact_match >= 0);
	*node = found;
	*previous = prev;

dbg_zone_exec_detail(
	char *name_str = (*node) ? knot_dname_to_str((*node)->owner)
				 : "(nil)";
	char *name_str2 = (*previous != NULL)
			  ? knot_dname_to_str((*previous)->owner)
			  : "(nil)";
dbg_zone_detail("Search function returned %d, node %s (%p) and prev: %s (%p)\n",
			exact_match, name_str, *node, name_str2, *previous);

	if (*node) {
		free(name_str);
	}
	if (*previous != NULL) {
		free(name_str2);
	}
);
	// there must be at least one node with domain name less or equal to
	// the searched name if the name belongs to the zone (the root)
	if (*node == NULL && *previous == NULL) {
		return KNOT_EOUTOFZONE;
	}

	/* This function was quite out of date. The find_in_tree() function
	 * may return NULL in the 'found' field, so we cannot search for the
	 * closest encloser from this node.
	 */

	if (exact_match) {
		*closest_encloser = *node;
	} else {
		if (!knot_dname_is_sub(name, zone->apex->owner)) {
			*node = NULL;
			*closest_encloser = NULL;
			return KNOT_EOUTOFZONE;
		}

		*closest_encloser = *previous;
		assert(*closest_encloser != NULL);

		int matched_labels = knot_dname_matched_labels((*closest_encloser)->owner,
							       name);
		while (matched_labels < knot_dname_labels((*closest_encloser)->owner, NULL)) {
			(*closest_encloser) =
				(*closest_encloser)->parent;
			assert(*closest_encloser);
		}
	}

	dbg_zone_verb("find_dname() returning %d\n", exact_match);

	return (exact_match)
	       ? ZONE_NAME_FOUND
	       : ZONE_NAME_NOT_FOUND;
}

/*----------------------------------------------------------------------------*/

zone_node_t *zone_contents_get_previous(const zone_contents_t *zone,
                                        const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	zone_node_t *found = NULL, *prev = NULL;

	int exact_match = zone_contents_find_in_tree(zone->nodes, name,
							    &found, &prev);
	assert(exact_match >= 0);
	assert(prev != NULL);

	return prev;
}

/*----------------------------------------------------------------------------*/

const zone_node_t *zone_contents_find_previous(const zone_contents_t *zone,
                                               const knot_dname_t *name)
{
	return zone_contents_get_previous(zone, name);
}

/*----------------------------------------------------------------------------*/

const zone_node_t *zone_contents_find_nsec3_node(const zone_contents_t *zone,
                                                 const knot_dname_t *name)
{
	return zone_contents_get_nsec3_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int zone_contents_find_nsec3_for_name(const zone_contents_t *zone,
                                      const knot_dname_t *name,
                                      const zone_node_t **nsec3_node,
                                      const zone_node_t **nsec3_previous)
{
	if (zone == NULL || name == NULL
	    || nsec3_node == NULL || nsec3_previous == NULL) {
		return KNOT_EINVAL;
	}

	// check if the NSEC3 tree is not empty
	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		dbg_zone("NSEC3 tree is empty.\n");
		return KNOT_ENSEC3CHAIN;
	}

	knot_dname_t *nsec3_name = knot_create_nsec3_owner(name, zone->apex->owner,
	                                                   node_rdataset(zone->apex,
	                                                   KNOT_RRTYPE_NSEC3PARAM));
	if (nsec3_name == NULL) {
		return KNOT_ENOMEM;
	}

dbg_zone_exec_verb(
	char *n = knot_dname_to_str(nsec3_name);
	dbg_zone_verb("NSEC3 node name: %s.\n", n);
	free(n);
);

	const zone_node_t *found = NULL, *prev = NULL;

	// create dummy node to use for lookup
	int exact_match = zone_tree_find_less_or_equal(
		zone->nsec3_nodes, nsec3_name, &found, &prev);
	assert(exact_match >= 0);

	knot_dname_free(&nsec3_name, NULL);

dbg_zone_exec_detail(
	if (found) {
		char *n = knot_dname_to_str(found->owner);
		dbg_zone_detail("Found NSEC3 node: %s.\n", n);
		free(n);
	} else {
		dbg_zone_detail("Found no NSEC3 node.\n");
	}

	if (prev) {
		assert(prev->owner);
		char *n = knot_dname_to_str(prev->owner);
		dbg_zone_detail("Found previous NSEC3 node: %s.\n", n);
		free(n);
	} else {
		dbg_zone_detail("Found no previous NSEC3 node.\n");
	}
);
	*nsec3_node = found;

	if (prev == NULL) {
		// either the returned node is the root of the tree, or it is
		// the leftmost node in the tree; in both cases node was found
		// set the previous node of the found node
		assert(exact_match);
		assert(*nsec3_node != NULL);
		*nsec3_previous = (*nsec3_node)->prev;
	} else {
		*nsec3_previous = prev;
	}

	dbg_zone_verb("find_nsec3_for_name() returning %d\n", exact_match);

	return (exact_match)
	       ? ZONE_NAME_FOUND
	       : ZONE_NAME_NOT_FOUND;
}

/*----------------------------------------------------------------------------*/

const zone_node_t *zone_contents_find_wildcard_child(const zone_contents_t *contents,
                                                     const zone_node_t *parent)
{
	if (contents == NULL || parent == NULL || parent->owner == NULL) {
		return NULL;
	}

	knot_dname_t wildcard[KNOT_DNAME_MAXLEN] = { 0x01, '*' };
	knot_dname_to_wire(wildcard + 2, parent->owner, KNOT_DNAME_MAXLEN - 2);
	return zone_contents_find_node(contents, wildcard);
}

/*----------------------------------------------------------------------------*/

int zone_contents_tree_apply_inorder(zone_contents_t *zone,
                                     zone_contents_apply_cb_t function, void *data)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return zone_tree_apply_inorder(zone->nodes, tree_apply_cb, &f);
}

/*----------------------------------------------------------------------------*/

int zone_contents_nsec3_apply_inorder(zone_contents_t *zone,
                                      zone_contents_apply_cb_t function, void *data)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return zone_tree_apply_inorder(zone->nsec3_nodes,
	                                    tree_apply_cb, &f);
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
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	int ret = recreate_normal_tree(from, contents);
	if (ret != KNOT_EOK) {
		zone_tree_free(&contents->nodes);
		free(contents);
		return ret;
	}

	if (from->nsec3_nodes) {
		ret = recreate_nsec3_tree(from, contents);
		if (ret != KNOT_EOK) {
			zone_tree_free(&contents->nodes);
			zone_tree_free(&contents->nsec3_nodes);
			free(contents);
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

	// free the zone tree, but only the structure
	dbg_zone("Destroying zone tree.\n");
	zone_tree_free(&(*contents)->nodes);
	dbg_zone("Destroying NSEC3 zone tree.\n");
	zone_tree_free(&(*contents)->nsec3_nodes);

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
			zone_contents_destroy_node_rrsets_from_tree,
			(void*)1);

		// Delete normal tree
		zone_tree_apply(
			(*contents)->nodes,
			zone_contents_destroy_node_rrsets_from_tree,
			(void*)1);
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
	if (knot_serial_compare(old_serial, new_serial) >= 0) {
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

zone_node_t *zone_contents_get_node_for_rr(zone_contents_t *zone, const knot_rrset_t *rrset)
{
	if (zone == NULL || rrset == NULL) {
		return NULL;
	}

	zone_node_t *node;
	const bool nsec3 = rrset_is_nsec3rel(rrset);
	if (!nsec3) {
		node = zone_contents_get_node(zone, rrset->owner);
	} else {
		node = zone_contents_get_nsec3_node(zone, rrset->owner);
	}

	if (node == NULL) {
		int ret = KNOT_EOK;
		node = node_new(rrset->owner, NULL);
		if (!nsec3) {
			ret = zone_contents_add_node(zone, node, 1);
		} else {
			ret = zone_contents_add_nsec3_node(zone, node);
		}
		if (ret != KNOT_EOK) {
			node_free(&node, NULL);
			return NULL;
		}

		return node;
	} else {
		return node;
	}
}

zone_node_t *zone_contents_find_node_for_rr(zone_contents_t *zone, const knot_rrset_t *rrset)
{
	if (zone == NULL || rrset == NULL) {
		return NULL;
	}

	zone_node_t *node;
	const bool nsec3 = rrset_is_nsec3rel(rrset);
	if (!nsec3) {
		node = zone_contents_get_node(zone, rrset->owner);
	} else {
		node = zone_contents_get_nsec3_node(zone, rrset->owner);
	}

	return node;
}
