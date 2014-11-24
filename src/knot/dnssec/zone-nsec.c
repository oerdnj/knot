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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "libknot/internal/base32hex.h"
#include "knot/common/debug.h"
#include "libknot/descriptor.h"
#include "libknot/dnssec/bitmap.h"
#include "libknot/internal/utils.h"
#include "libknot/packet/wire.h"
#include "libknot/rrtype/soa.h"
#include "libknot/rrtype/nsec3.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/nsec3-chain.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone-diff.h"

/*!
 * \brief Deletes NSEC3 chain if NSEC should be used.
 *
 * \param zone       Zone to fix.
 * \param changeset  Changeset to be used.
 * \return KNOT_E*
 */
static int delete_nsec3_chain(const zone_contents_t *zone,
                              changeset_t *changeset)
{
	assert(zone);
	assert(changeset);

	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_EOK;
	}

	dbg_dnssec_detail("deleting NSEC3 chain\n");
	zone_tree_t *empty_tree = zone_tree_create();
	if (!empty_tree) {
		return KNOT_ENOMEM;
	}

	int result = zone_tree_add_diff(zone->nsec3_nodes, empty_tree,
	                                     changeset);

	zone_tree_free(&empty_tree);

	return result;
}

/* - helper functions ------------------------------------------------------ */

/*!
 * \brief Check if NSEC3 is enabled for given zone.
 */
bool knot_is_nsec3_enabled(const zone_contents_t *zone)
{
	return node_rrtype_exists(zone->apex, KNOT_RRTYPE_NSEC3PARAM);
}

/*!
 * \brief Get minimum TTL from zone SOA.
 * \note Value should be used for NSEC records.
 */
static bool get_zone_soa_min_ttl(const zone_contents_t *zone,
                                 uint32_t *ttl)
{
	assert(zone);
	assert(zone->apex);
	assert(ttl);

	zone_node_t *apex = zone->apex;
	const knot_rdataset_t *soa = node_rdataset(apex, KNOT_RRTYPE_SOA);
	if (!soa) {
		return false;
	}

	uint32_t result =  knot_soa_minimum(soa);
	if (result == 0) {
		return false;
	}

	*ttl = result;
	return true;
}

/* - public API ------------------------------------------------------------ */

/*!
 * \brief Create NSEC3 owner name from regular owner name.
 *
 * \param owner      Node owner name.
 * \param zone_apex  Zone apex name.
 * \param params     Params for NSEC3 hashing function.
 *
 * \return NSEC3 owner name, NULL in case of error.
 */
knot_dname_t *knot_create_nsec3_owner(const knot_dname_t *owner,
                                      const knot_dname_t *zone_apex,
                                      const knot_rdataset_t *params)
{
	if (owner == NULL || zone_apex == NULL || params == NULL) {
		return NULL;
	}

	uint8_t *hash = NULL;
	size_t hash_size = 0;
	int owner_size = knot_dname_size(owner);

	if (owner_size < 0) {
		return NULL;
	}

	if (knot_nsec3_hash(params, owner, owner_size, &hash, &hash_size)
	    != KNOT_EOK) {
		return NULL;
	}

	knot_dname_t *result = knot_nsec3_hash_to_dname(hash, hash_size, zone_apex);
	free(hash);

	return result;
}

/*!
 * \brief Create NSEC3 owner name from hash and zone apex.
 */
knot_dname_t *knot_nsec3_hash_to_dname(const uint8_t *hash, size_t hash_size,
                                       const knot_dname_t *zone_apex)
{
	assert(zone_apex);

	// encode raw hash to first label

	uint8_t label[KNOT_DNAME_MAXLEN];
	int32_t label_size;
	label_size = base32hex_encode(hash, hash_size, label, sizeof(label));
	if (label_size <= 0) {
		return NULL;
	}

	// allocate result

	size_t zone_apex_size = knot_dname_size(zone_apex);
	size_t result_size = 1 + label_size + zone_apex_size;
	knot_dname_t *result = malloc(result_size);
	if (!result) {
		return NULL;
	}

	// build the result

	uint8_t *write = result;

	*write = (uint8_t)label_size;
	write += 1;
	memcpy(write, label, label_size);
	write += label_size;
	memcpy(write, zone_apex, zone_apex_size);
	write += zone_apex_size;

	assert(write == result + result_size);
	knot_dname_to_lower(result);

	return result;
}

/*!
 * \brief Create NSEC or NSEC3 chain in the zone.
 */
int knot_zone_create_nsec_chain(zone_update_t *up,
                                const knot_zone_keys_t *zone_keys,
                                const knot_dnssec_policy_t *policy)
{
#warning redo api getters + iters
//	if (!up || !policy || !zone_keys) {
//		return KNOT_EINVAL;
//	}

//	uint32_t nsec_ttl = 0;
//	if (!get_zone_soa_min_ttl(zone, &nsec_ttl)) {
//		return KNOT_EINVAL;
//	}

//	int result;
//	const bool nsec3_enabled = knot_is_nsec3_enabled(zone);
//	if (nsec3_enabled) {
//		result = knot_nsec3_create_chain(up, nsec_ttl);
//	} else {
//		result = knot_nsec_create_chain(up, nsec_ttl);
//	}

//	if (result == KNOT_EOK && !nsec3_enabled) {
//		result = delete_nsec3_chain(zone, changeset);
//	}

//	if (result == KNOT_EOK) {
//		// Mark removed NSEC3 nodes, so that they are not signed later
//		result = mark_removed_nsec3(changeset, zone);
//	}

//	if (result != KNOT_EOK) {
//		return result;
//	}

//	// Sign newly created records right away
//	return knot_zone_sign_nsecs_in_changeset(zone_keys, policy, changeset);
}
