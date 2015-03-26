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

#include "dnssec/error.h"
#include "dnssec/nsec.h"
#include "libknot/internal/base32hex.h"
#include "libknot/descriptor.h"
#include "libknot/packet/wire.h"
#include "libknot/rrtype/nsec3.h"
#include "libknot/rrtype/soa.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/nsec3-chain.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone-diff.h"

static int remove_rrsets_from(const zone_node_t *node, zone_update_t *update)
{
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		const knot_rrset_t rr = node_rrset_at(node, i);
		int ret = zone_update_remove(update, &rr);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Deletes NSEC3 chain if NSEC should be used.
 *
 * \param zone       Zone to fix.
 * \param changeset  Changeset to be used.
 * \return KNOT_E*
 */
static int delete_nsec3_chain(zone_update_t *update)
{
	assert(update);

	zone_update_iter_t itt;
	const bool read_only = false;
	int result = zone_update_iter_nsec3(&itt, update, read_only);
	if (result != KNOT_EOK) {
		return result;
	}
	const zone_node_t *n = zone_update_iter_val(&itt);
	while (n) {
		result = remove_rrsets_from(n, update);
		if (result == KNOT_EOK) {
			result = zone_update_iter_next(&itt);
		}
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (result != KNOT_EOK) {
		zone_update_iter_finish(&itt);
		return result;
	}
	return zone_update_iter_finish(&itt);
}

/* - helper functions ------------------------------------------------------ */

/*!
 * \brief Check if NSEC3 is enabled for given zone.
 */
bool knot_is_nsec3_enabled(zone_update_t *update)
{
	const zone_node_t *apex = zone_update_get_apex(update);
	return node_rrtype_exists(apex, KNOT_RRTYPE_NSEC3PARAM);
}

/*!
 * \brief Get minimum TTL from zone SOA.
 * \note Value should be used for NSEC records.
 */
static uint32_t const get_zone_soa_min_ttl(zone_update_t *update)
{
	assert(update);
	const zone_node_t *apex = zone_update_get_apex(update);
	const knot_rdataset_t *soa = node_rdataset(apex, KNOT_RRTYPE_SOA);

	return knot_soa_minimum(soa);
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

	int owner_size = knot_dname_size(owner);
	if (owner_size < 0) {
		return NULL;
	}

	dnssec_binary_t data = { 0 };
	data.data = (uint8_t *)owner;
	data.size = owner_size;

	dnssec_binary_t hash = { 0 };
	dnssec_nsec3_params_t xparams = {
		.algorithm = knot_nsec3param_algorithm(params, 0),
		.flags = knot_nsec3param_flags(params, 0),
		.iterations = knot_nsec3param_iterations(params, 0),
		.salt = {
			.data = (uint8_t *)knot_nsec3param_salt(params, 0),
			.size = knot_nsec3param_salt_length(params, 0)
		}
	};

	int r = dnssec_nsec3_hash(&data, &xparams, &hash);
	if (r != DNSSEC_EOK) {
		return NULL;
	}

	knot_dname_t *result = knot_nsec3_hash_to_dname(hash.data, hash.size, zone_apex);

	dnssec_binary_free(&hash);

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
int knot_zone_create_nsec_chain(zone_update_t *update,
                                const zone_keyset_t *zone_keys,
                                const kdnssec_ctx_t *dnssec_ctx)
{
	if (!update) {
		return KNOT_EINVAL;
	}

	const uint32_t nsec_ttl = get_zone_soa_min_ttl(update);

	int result;
	const bool nsec3_enabled = knot_is_nsec3_enabled(update);

	if (nsec3_enabled) {
		result = knot_nsec3_create_chain(update, nsec_ttl);
	} else {
		result = knot_nsec_create_chain(update, nsec_ttl);
	}

	if (result == KNOT_EOK && !nsec3_enabled) {
		result = delete_nsec3_chain(update);
	}

	return result;
}
