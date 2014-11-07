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

#include "common/base32hex.h"
#include "common/macros.h"
#include "knot/dnssec/nsec3-chain.h"
#include "libknot/dname.h"
#include "libknot/packet/wire.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone-diff.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/dnssec/bitmap.h"
#include "libknot/rrtype/nsec3.h"

/* - Forward declarations --------------------------------------------------- */

static int create_nsec3_rrset(knot_rrset_t *rrset,
                              knot_dname_t *dname,
                              const knot_rdataset_t *,
                              const bitmap_t *,
                              const uint8_t *,
                              uint32_t);

/* - Helper functions ------------------------------------------------------- */

/* - NSEC3 node comparison -------------------------------------------------- */

/*!
 * \brief Perform some basic checks that the node is a valid NSEC3 node.
 */
inline static bool valid_nsec3_node(const zone_node_t *node)
{
	assert(node);

	if (node->rrset_count > 2) {
		return false;
	}

	const knot_rdataset_t *nsec3 = node_rdataset(node, KNOT_RRTYPE_NSEC3);
	if (nsec3 == NULL) {
		return false;
	}

	if (nsec3->rr_count != 1) {
		return false;
	}

	return true;
}

/*!
 * \brief Check if two nodes are equal.
 */
static bool are_nsec3_nodes_equal(const zone_node_t *a, const zone_node_t *b)
{
	if (!(valid_nsec3_node(a) && valid_nsec3_node(b))) {
		return false;
	}

	knot_rrset_t a_rrset = node_rrset(a, KNOT_RRTYPE_NSEC3);
	knot_rrset_t b_rrset = node_rrset(b, KNOT_RRTYPE_NSEC3);
	return knot_rrset_equal(&a_rrset, &b_rrset, KNOT_RRSET_COMPARE_WHOLE);
}

/*!
 * \brief Check whether at least one RR type in node should be signed,
 *        used when signing with NSEC3.
 *
 * \param node  Node for which the check is done.
 *
 * \return true/false.
 */
static bool node_should_be_signed_nsec3(const zone_node_t *n)
{
	for (int i = 0; i < n->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(n, i);
		if (rrset.type == KNOT_RRTYPE_NSEC ||
		    rrset.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		bool should_sign = false;
		int ret = knot_zone_sign_rr_should_be_signed(n, &rrset,
		                                             &should_sign);
		assert(ret == KNOT_EOK); // No tree inside the function, no fail
		if (should_sign) {
			return true;
		}
	}

	return false;
}

/* - RRSIGs handling for NSEC3 ---------------------------------------------- */

/*!
 * \brief Shallow copy NSEC3 signatures from the one node to the second one.
 *        Just sets the pointer, needed only for comparison.
 */
static int shallow_copy_signature(const zone_node_t *from, zone_node_t *to)
{
	assert(valid_nsec3_node(from));
	assert(valid_nsec3_node(to));

	knot_rrset_t from_sig = node_rrset(from, KNOT_RRTYPE_RRSIG);
	if (knot_rrset_empty(&from_sig)) {
		return KNOT_EOK;
	}
	return node_add_rrset(to, &from_sig, NULL);
}

/*!
 * \brief Reuse signatatures by shallow copying them from one tree to another.
 */
static int copy_signatures(const zone_tree_t *from, zone_tree_t *to)
{
	if (zone_tree_is_empty(from)) {
		return KNOT_EOK;
	}

	assert(to);

	bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(from, sorted);

	for (/* NOP */; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		zone_node_t *node_from = (zone_node_t *)*hattrie_iter_val(it);
		zone_node_t *node_to = NULL;

		zone_tree_get(to, node_from->owner, &node_to);
		if (node_to == NULL) {
			continue;
		}

		if (!are_nsec3_nodes_equal(node_from, node_to)) {
			continue;
		}

		int ret = shallow_copy_signature(node_from, node_to);
		if (ret != KNOT_EOK) {
			hattrie_iter_free(it);
			return ret;
		}
	}

	hattrie_iter_free(it);
	return KNOT_EOK;
}

/*!
 * \brief Custom NSEC3 tree free function.
 *
 */
static void free_nsec3_tree(zone_tree_t *nodes)
{
	assert(nodes);

	bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(nodes, sorted);
	for (/* NOP */; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		zone_node_t *node = (zone_node_t *)*hattrie_iter_val(it);
		// newly allocated NSEC3 nodes
		knot_rdataset_t *nsec3 = node_rdataset(node, KNOT_RRTYPE_NSEC3);
		knot_rdataset_t *rrsig = node_rdataset(node, KNOT_RRTYPE_RRSIG);
		knot_rdataset_clear(nsec3, NULL);
		knot_rdataset_clear(rrsig, NULL);
		node_free(&node, NULL);
	}

	hattrie_iter_free(it);
	zone_tree_free(&nodes);
}

/* - NSEC3 nodes construction ----------------------------------------------- */

/*!
 * \brief Get NSEC3 RDATA size.
 */
static size_t nsec3_rdata_size(const knot_rdataset_t *params,
                               const bitmap_t *rr_types)
{
	assert(params);
	assert(rr_types);

	return 6 + knot_nsec3param_salt_length(params, 0)
	       + knot_nsec3_hash_length(knot_nsec3param_algorithm(params, 0))
	       + knot_bitmap_size(rr_types);
}

/*!
 * \brief Fill NSEC3 RDATA.
 *
 * \note Content of next hash field is not changed.
 */
static void nsec3_fill_rdata(uint8_t *rdata, const knot_rdataset_t *params,
                             const bitmap_t *rr_types,
                             const uint8_t *next_hashed, uint32_t ttl)
{
	assert(rdata);
	assert(params);
	assert(rr_types);

	const uint8_t algo = knot_nsec3param_algorithm(params, 0);
	uint8_t hash_length = knot_nsec3_hash_length(algo);

	*rdata = algo;                                    // hash algorithm
	rdata += 1;
	*rdata = 0;                                       // flags
	rdata += 1;
	knot_wire_write_u16(rdata,
	                    knot_nsec3param_iterations(params, 0));   // iterations
	rdata += 2;
	const uint8_t salt_len = knot_nsec3param_salt_length(params, 0);
	*rdata = salt_len;  // salt length
	rdata += 1;
	memcpy(rdata, knot_nsec3param_salt(params, 0), salt_len); // salt
	rdata += salt_len;
	*rdata = hash_length;                             // hash length
	rdata += 1;
	if (next_hashed) {
		memcpy(rdata, next_hashed, hash_length);  // hash (unknown)
	} else {
		memset(rdata, '\0', hash_length);
	}
	rdata += hash_length;
	bitmap_write(rr_types, rdata);                    // RR types bit map
}

/*!
 * \brief Creates NSEC3 RRSet.
 *
 * \param owner        Owner for the RRSet.
 * \param params       Parsed NSEC3PARAM.
 * \param rr_types     Bitmap.
 * \param next_hashed  Next hashed.
 * \param ttl          TTL for the RRSet.
 *
 * \return Pointer to created RRSet on success, NULL on errors.
 */
static int create_nsec3_rrset(knot_rrset_t *rrset,
                              knot_dname_t *owner,
                              const knot_rdataset_t *params,
                              const bitmap_t *rr_types,
                              const uint8_t *next_hashed,
                              uint32_t ttl)
{
	assert(rrset);
	assert(owner);
	assert(params);
	assert(rr_types);

	knot_rrset_init(rrset, owner, KNOT_RRTYPE_NSEC3, KNOT_CLASS_IN);

	size_t rdata_size = nsec3_rdata_size(params, rr_types);
	uint8_t rdata[rdata_size];
	nsec3_fill_rdata(rdata, params, rr_types, next_hashed, ttl);

	return knot_rrset_add_rdata(rrset, rdata, rdata_size, ttl, NULL);
}

/*!
 * \brief Create NSEC3 node.
 */
static zone_node_t *create_nsec3_node(knot_dname_t *owner,
                                      const knot_rdataset_t *nsec3_params,
                                      zone_node_t *apex_node,
                                      const bitmap_t *rr_types,
                                      uint32_t ttl)
{
	assert(owner);
	assert(nsec3_params);
	assert(apex_node);
	assert(rr_types);

	zone_node_t *new_node = node_new(owner, NULL);
	if (!new_node) {
		return NULL;
	}

	node_set_parent(new_node, apex_node);

	knot_rrset_t nsec3_rrset;
	int ret = create_nsec3_rrset(&nsec3_rrset, owner, nsec3_params,
	                             rr_types, NULL, ttl);
	if (ret != KNOT_EOK) {
		node_free(&new_node, NULL);
		return NULL;
	}

	ret = node_add_rrset(new_node, &nsec3_rrset, NULL);
	knot_rrset_clear(&nsec3_rrset, NULL);
	if (ret != KNOT_EOK) {
		node_free(&new_node, NULL);
		return NULL;
	}

	return new_node;
}

/*!
 * \brief Create new NSEC3 node for given regular node.
 *
 * \param node       Node for which the NSEC3 node is created.
 * \param apex       Zone apex node.
 * \param params     NSEC3 hash function parameters.
 * \param ttl        TTL of the new NSEC3 node.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static zone_node_t *create_nsec3_node_for_node(zone_node_t *node,
                                               zone_node_t *apex,
                                               const knot_rdataset_t *params,
                                               uint32_t ttl)
{
	assert(node);
	assert(apex);
	assert(params);

	knot_dname_t *nsec3_owner;
	nsec3_owner = knot_create_nsec3_owner(node->owner, apex->owner, params);
	if (!nsec3_owner) {
		return NULL;
	}

	bitmap_t rr_types = { 0 };
	bitmap_add_node_rrsets(&rr_types, node);
	if (node->rrset_count > 0 && node_should_be_signed_nsec3(node)) {
		knot_bitmap_add_type(&rr_types, KNOT_RRTYPE_RRSIG);
	}
	if (node == apex) {
		knot_bitmap_add_type(&rr_types, KNOT_RRTYPE_DNSKEY);
	}

	zone_node_t *nsec3_node;
	nsec3_node = create_nsec3_node(nsec3_owner, params, apex, &rr_types, ttl);

	return nsec3_node;
}

/* - NSEC3 chain creation --------------------------------------------------- */

/*!
 * \brief Connect two nodes by filling 'hash' field of NSEC3 RDATA of the node.
 *
 * \param a     First node.
 * \param b     Second node (immediate follower of a).
 * \param data  Unused parameter.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec3_nodes(zone_node_t *a, zone_node_t *b,
                               nsec_chain_iterate_data_t *data)
{
	assert(a);
	assert(b);
	UNUSED(data);

	assert(a->rrset_count == 1);

	knot_rdataset_t *a_rrs = node_rdataset(a, KNOT_RRTYPE_NSEC3);
	assert(a_rrs);
	uint8_t algorithm = knot_nsec3_algorithm(a_rrs, 0);
	if (algorithm == 0) {
		return KNOT_EINVAL;
	}

	uint8_t *raw_hash = NULL;
	uint8_t raw_length = 0;
	knot_nsec3_next_hashed(a_rrs, 0, &raw_hash, &raw_length);
	if (raw_hash == NULL) {
		return KNOT_EINVAL;
	}

	assert(raw_length == knot_nsec3_hash_length(algorithm));

	uint8_t *b32_hash = (uint8_t *)knot_dname_to_str_alloc(b->owner);
	size_t b32_length = knot_nsec3_hash_b32_length(algorithm);
	if (!b32_hash) {
		return KNOT_ENOMEM;
	}

	int32_t written = base32hex_decode(b32_hash, b32_length,
	                                   raw_hash, raw_length);

	free(b32_hash);

	if (written != raw_length) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

/*!
 * \brief Create NSEC3 node for each regular node in the zone.
 *
 * \param zone         Zone.
 * \param ttl          TTL for the created NSEC records.
 * \param nsec3_nodes  Tree whereto new NSEC3 nodes will be added.
 * \param chgset       Changeset used for possible NSEC removals
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_nsec3_nodes(zone_update_t *up, uint32_t ttl,
                              zone_tree_t *nsec3_nodes)
{
	assert(up);
	assert(nsec3_nodes);

	const zone_node_t *apex = zone_update_get_node(up, up->zone->name);
	if (apex == NULL) {
		return KNOT_ENOMEM;
	}

	const knot_rdataset_t *params = node_rdataset(apex, KNOT_RRTYPE_NSEC3PARAM);
	assert(params);

	int result = KNOT_EOK;
	
#warning redo iter

//	const bool sorted = false;
//	hattrie_iter_t *it = hattrie_iter_begin(zone->nodes, sorted);
//	while (!hattrie_iter_finished(it)) {
//		zone_node_t *node = (zone_node_t *)*hattrie_iter_val(it);

//		/*!
//		 * Remove possible NSEC from the node. (Do not allow both NSEC
//		 * and NSEC3 in the zone at once.)
//		 */
//		result = knot_nsec_changeset_remove(node, chgset);
//		if (result != KNOT_EOK) {
//			break;
//		}
//		if (node_rrtype_exists(node, KNOT_RRTYPE_NSEC)) {
//			node->flags |= NODE_FLAGS_REMOVED_NSEC;
//		}
//		if (node->flags & NODE_FLAGS_NONAUTH || node->flags & NODE_FLAGS_EMPTY) {
//			hattrie_iter_next(it);
//			continue;
//		}

//		zone_node_t *nsec3_node;
//		nsec3_node = create_nsec3_node_for_node(node, zone->apex,
//		                                        params, ttl);
//		if (!nsec3_node) {
//			result = KNOT_ENOMEM;
//			break;
//		}

//		result = zone_tree_insert(nsec3_nodes, nsec3_node);
//		if (result != KNOT_EOK) {
//			break;
//		}

//		hattrie_iter_next(it);
//	}

//	hattrie_iter_free(it);

//	/* Rebuild index over nsec3 nodes. */
//	hattrie_build_index(nsec3_nodes);

//	return result;
}

/*!
 * \brief Checks if NSEC3 should be generated for this node.
 *
 * \retval true if the node has no children and contains no RRSets or only
 *         RRSIGs and NSECs.
 * \retval false otherwise.
 */
static bool nsec3_is_empty(zone_node_t *node)
{
	if (node->children > 0) {
		return false;
	}

	return knot_nsec_empty_nsec_and_rrsigs_in_node(node);
}

/* - Public API ------------------------------------------------------------- */

/*!
 * \brief Create new NSEC3 chain, add differences from current into a changeset.
 */
int knot_nsec3_create_chain(zone_update_t *up, uint32_t ttl)
{
#warning redo iter
//	assert(zone);
//	assert(changeset);

//	int result;

//	zone_tree_t *nsec3_nodes = zone_tree_create();
//	if (!nsec3_nodes) {
//		return KNOT_ENOMEM;
//	}

//	result = create_nsec3_nodes(up, ttl, nsec3_nodes);
//	if (result != KNOT_EOK) {
//		free_nsec3_tree(nsec3_nodes);
//		return result;
//	}

//	reset_nodes(zone);

//	result = knot_nsec_chain_iterate_create(nsec3_nodes,
//	                                        connect_nsec3_nodes, NULL);
//	if (result != KNOT_EOK) {
//		free_nsec3_tree(nsec3_nodes);
//		return result;
//	}

//	copy_signatures(zone->nsec3_nodes, nsec3_nodes);

//	result = zone_tree_add_diff(zone->nsec3_nodes, nsec3_nodes,
//	                                 changeset);

//	free_nsec3_tree(nsec3_nodes);

//	return result;
}
