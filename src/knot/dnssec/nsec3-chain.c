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

#include "dnssec/nsec.h"
#include "libknot/internal/base32hex.h"
#include "libknot/internal/macros.h"
#include "libknot/internal/namedb/namedb.h"
#include "libknot/internal/namedb/namedb_trie.h"
#include "knot/dnssec/nsec3-chain.h"
#include "libknot/dname.h"
#include "libknot/packet/wire.h"
#include "libknot/rrtype/nsec3.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/node.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/dnssec/zone-nsec.h"

/* - Forward declarations --------------------------------------------------- */

static int create_nsec3_rrset(knot_rrset_t *rrset,
                              knot_dname_t *dname,
                              const knot_rdataset_t *,
                              const dnssec_nsec_bitmap_t *,
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
		assert(rrset.type != KNOT_RRTYPE_NSEC);
		if (rrset.type == KNOT_RRTYPE_RRSIG) {
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
 * \brief Reuse signatures by shallow copying them from one tree to another.
 */
static int copy_signatures(zone_update_t *from, zone_tree_t *to)
{
	assert(from);
	assert(to);

	zone_update_iter_t it;
	int ret = zone_update_iter_nsec3(&it, from);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (zone_update_iter_val(&it) == NULL) {
		zone_update_iter_finish(&it);
		// Nothing to iterate over.
		return KNOT_EOK;
	}

	const zone_node_t *node_from = zone_update_iter_val(&it);
	while (node_from) {
		zone_node_t *node_to = zone_tree_get(to, node_from->owner);
		if (node_to) {
			if (are_nsec3_nodes_equal(node_from, node_to)) {
				ret = shallow_copy_signature(node_from, node_to);
				if (ret != KNOT_EOK) {
					break;
				}
			}
		}
		ret = zone_update_iter_next(&it);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	zone_update_iter_finish(&it);
	return ret;
}

/*!
 * \brief Custom NSEC3 tree free function.
 *
 */
static int free_nsec3_tree(zone_tree_t *nodes)
{
	assert(nodes);

	namedb_txn_t tx;
	int ret = nodes->api->txn_begin(nodes->db, &tx, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	namedb_iter_t *it = nodes->api->iter_begin(&tx, 0);
	if (it == NULL) {
		return ret;
	}

	while (it) {
		namedb_val_t val;
		nodes->api->iter_val(it, &val);
		zone_node_t *node = (zone_node_t *)val.data;
		// newly allocated NSEC3 nodes
		knot_rdataset_t *nsec3 = node_rdataset(node, KNOT_RRTYPE_NSEC3);
		knot_rdataset_t *rrsig = node_rdataset(node, KNOT_RRTYPE_RRSIG);
		knot_rdataset_clear(nsec3, NULL);
		knot_rdataset_clear(rrsig, NULL);
		node_free(&node, NULL);
		it = nodes->api->iter_next(&it);
	}

	nodes->api->txn_abort(&tx);
	zone_tree_clear(nodes);
	return KNOT_EOK;
}

/* - NSEC3 nodes construction ----------------------------------------------- */

/*!
 * \brief Get NSEC3 RDATA size.
 */
static size_t nsec3_rdata_size(const knot_rdataset_t *params,
                               const dnssec_nsec_bitmap_t *rr_types)
{
	assert(params);
	assert(rr_types);

	return 6 + knot_nsec3param_salt_length(params, 0)
	       + dnssec_nsec3_hash_length(knot_nsec3param_algorithm(params, 0))
	       + dnssec_nsec_bitmap_size(rr_types);
}

/*!
 * \brief Fill NSEC3 RDATA.
 *
 * \note Content of next hash field is not changed.
 */
static void nsec3_fill_rdata(uint8_t *rdata, const knot_rdataset_t *params,
                             const dnssec_nsec_bitmap_t *rr_types,
                             const uint8_t *next_hashed, uint32_t ttl)
{
	assert(rdata);
	assert(params);
	assert(rr_types);

	const uint8_t algo = knot_nsec3param_algorithm(params, 0);
	uint8_t hash_length = dnssec_nsec3_hash_length(algo);

	*rdata = algo;                                    // hash algorithm
	rdata += 1;
	*rdata = 0;                                       // flags
	rdata += 1;
	wire_write_u16(rdata, knot_nsec3param_iterations(params, 0));   // iterations
	rdata += 2;
	const uint8_t salt_len = knot_nsec3param_salt_length(params, 0);
	*rdata = salt_len;  // salt length
	rdata += 1;
	memcpy(rdata, knot_nsec3param_salt(params, 0), salt_len); // salt
	rdata += salt_len;
	*rdata = hash_length;                             // hash length
	rdata += 1;
	/*memset(rdata, '\0', hash_len);*/                // hash (unknown)
	if (next_hashed) {
		memcpy(rdata, next_hashed, hash_length);  // hash (unknown)
	} else {
		memset(rdata, '\0', hash_length);
	}
	rdata += hash_length;
	dnssec_nsec_bitmap_write(rr_types, rdata);        // RR types bit map
}

/*!
 * \brief Checks if NSEC3 should be generated for this node.
 *
 * \retval true if the node has no children and contains no RRSets or only
 *         RRSIGs and NSECs.
 * \retval false otherwise.
 */
static bool generate_nsec3(zone_update_t *update, const zone_node_t *node)
{
	return !(node->flags & NODE_FLAGS_NONAUTH) && zone_update_has_children(update, node->owner);
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
                              const dnssec_nsec_bitmap_t *rr_types,
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
                                      const dnssec_nsec_bitmap_t *rr_types,
                                      uint32_t ttl)
{
	assert(owner);
	assert(nsec3_params);
	assert(rr_types);

	zone_node_t *new_node = node_new(owner, NULL);
	if (!new_node) {
		return NULL;
	}

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
static zone_node_t *create_nsec3_node_for_node(const zone_node_t *node,
                                               const knot_dname_t *zone_name,
                                               const knot_rdataset_t *params,
                                               uint32_t ttl)
{
	assert(node);
	assert(params);

	knot_dname_t *nsec3_owner;
	nsec3_owner = knot_create_nsec3_owner(node->owner, zone_name, params);
	if (!nsec3_owner) {
		return NULL;
	}

	dnssec_nsec_bitmap_t *rr_types = dnssec_nsec_bitmap_new();
	if (!rr_types) {
		return NULL;
	}

	bitmap_add_node_rrsets(rr_types, node);
	if (node->rrset_count > 0 && node_should_be_signed_nsec3(node)) {
		dnssec_nsec_bitmap_add(rr_types, KNOT_RRTYPE_RRSIG);
	}
	if (node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		dnssec_nsec_bitmap_add(rr_types, KNOT_RRTYPE_DNSKEY);
	}

	zone_node_t *nsec3_node;
	nsec3_node = create_nsec3_node(nsec3_owner, params, rr_types, ttl);
	dnssec_nsec_bitmap_free(rr_types);

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
static int connect_nsec3_nodes(const zone_node_t *a, const zone_node_t *b,
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

	assert(raw_length == dnssec_nsec3_hash_length(algorithm));

	char *b32_hash = knot_dname_to_str_alloc(b->owner);
	if (!b32_hash) {
		return KNOT_ENOMEM;
	}

	char *b32_end = strchr(b32_hash, '.');
	if (!b32_end) {
		free(b32_hash);
		return KNOT_EINVAL;
	}

	size_t b32_length = b32_end - b32_hash;
	int32_t written = base32hex_decode((uint8_t *)b32_hash, b32_length,
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
static int create_nsec3_nodes(zone_update_t *update, uint32_t ttl,
                              zone_tree_t *nsec3_nodes)
{
	assert(update);
	assert(nsec3_nodes);

	const zone_node_t *apex = zone_update_get_apex(update);
	const knot_rdataset_t *params = node_rdataset(apex, KNOT_RRTYPE_NSEC3PARAM);
	assert(params);

	int result = KNOT_EOK;

	zone_update_iter_t it;
	const bool read_only = true;
	result = zone_update_iter(&it, update, read_only);
	if (result != KNOT_EOK) {
		return result;
	}
	
	const zone_node_t *node = zone_update_iter_val(&it);
	while (node) {
		if (generate_nsec3(update, node)) {
			zone_node_t *nsec3_node;
			nsec3_node = create_nsec3_node_for_node(node, apex->owner,
			                                        params, ttl);
			if (!nsec3_node) {
				result = KNOT_ENOMEM;
				break;
			}

			result = zone_tree_insert(nsec3_nodes, nsec3_node);
			if (result != KNOT_EOK) {
				break;
			}
		}
		result = zone_update_iter_next(&it);
		if (result != KNOT_EOK) {
			break;
		}
		node = zone_update_iter_val(&it);
	}

	zone_update_iter_finish(&it);
	return result;
}

static int remove_nsecs(zone_update_t *update)
{
	zone_update_iter_t it;
	const bool read_only = false;
	int ret = zone_update_iter(&it, update, read_only);
	if (ret != KNOT_EOK) {
		return ret;
	}
	// Need non-empty zone.
	assert(zone_update_iter_val(&it));

	const zone_node_t *n = zone_update_iter_val(&it);
	while (n) {
		if (node_rrtype_exists(n, KNOT_RRTYPE_NSEC)) {
			ret = knot_nsec_changeset_remove(n, update);
			if (ret != KNOT_EOK) {
				zone_update_iter_finish(&it);
				return ret;
			}
		}
		ret = zone_update_iter_next(&it);
		if (ret != KNOT_EOK) {
			zone_update_iter_finish(&it);
			return ret;
		}
	}

	return zone_update_iter_finish(&it);
}

static int create_chain_from_tree(zone_tree_t *nsec3_nodes, zone_update_t *update) {
	// Create fake zone update so that we can reuse the API.
	zone_contents_t contents = { .nsec3_nodes = nsec3_nodes };
	zone_t zone = { .contents = &contents };
	zone_update_t fake_up = { .zone = &zone, .flags = UPDATE_INCREMENTAL, .change = update->change };
	return knot_nsec_chain_iterate_create(&fake_up, connect_nsec3_nodes, NULL);
}

/* - Public API ------------------------------------------------------------- */

/*!
 * \brief Create new NSEC3 chain, add differences from current into a changeset.
 */
int knot_nsec3_create_chain(zone_update_t *update, uint32_t ttl)
{
	assert(update);

	// Remove possible NSEC records.
	int result = remove_nsecs(update);
	if (result != KNOT_EOK) {
		return result;
	}

	zone_tree_t nsec3_nodes;
	result = zone_tree_init(&nsec3_nodes, namedb_trie_api(), NULL);
	if (result != KNOT_EOK) {
		return result;
	}

	result = create_nsec3_nodes(update, ttl, &nsec3_nodes);
	if (result != KNOT_EOK) {
		free_nsec3_tree(&nsec3_nodes);
		return result;
	}

	result = create_chain_from_tree(&nsec3_nodes, update);
	if (result != KNOT_EOK) {
		free_nsec3_tree(&nsec3_nodes);
		return result;
	}

	result = copy_signatures(update, &nsec3_nodes);
	if (result != KNOT_EOK) {
		free_nsec3_tree(&nsec3_nodes);
		return result;
	}

#warning DIFF against the update, not two trees.
//	result = zone_tree_add_diff(zone->nsec3_nodes, nsec3_nodes,
//	                                 changeset);

	free_nsec3_tree(&nsec3_nodes);

	return result;
}
