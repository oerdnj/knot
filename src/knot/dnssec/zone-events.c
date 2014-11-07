/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <time.h>

#include "common/mem.h"
#include "knot/conf/conf.h"
#include "libknot/dnssec/policy.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "common/debug.h"
#include "knot/zone/zone.h"

static int zone_sign(zone_update_t *up, const bool force, uint32_t *refresh_at)
{
	assert(up);
	assert(refresh_at);

	log_zone_info(up->zone->name, "DNSSEC, signing started");

	// Init needed structs
	knot_zone_keys_t zone_keys;
	knot_init_zone_keys(&zone_keys);
	knot_dnssec_policy_t policy = { '\0' };
	int result = init_dnssec_structs(up->zone->contents, up->zone->conf, &zone_keys, &policy,
	                                 0, force);
	if (result != KNOT_EOK) {
		return result;
	}

	// generate NSEC records
	result = knot_zone_create_nsec_chain(up, &zone_keys, &policy);
	if (result != KNOT_EOK) {
		log_zone_error(up->zone->name, "DNSSEC, failed to create NSEC(3) chain (%s)",
		               knot_strerror(result));
		knot_free_zone_keys(&zone_keys);
		return result;
	}

	// add missing signatures
	result = knot_zone_sign(up, &zone_keys, &policy, refresh_at);
	if (result != KNOT_EOK) {
		log_zone_error(up->zone->name, "DNSSEC, failed to sign the zone (%s)",
		               knot_strerror(result));
		knot_free_zone_keys(&zone_keys);
		return result;
	}

	// Check if only SOA changed
#warning removed, double check the need

	// update SOA if there were any changes

	knot_free_zone_keys(&zone_keys);
	dbg_dnssec_detail("zone signed: changes=%zu\n",
	                  changeset_size(out_ch));

	log_zone_info(up->zone->name, "DNSSEC, successfully signed");

	return KNOT_EOK;
}

int init_dnssec_structs(const zone_contents_t *zone,
                        const conf_zone_t *config,
                        knot_zone_keys_t *zone_keys,
                        knot_dnssec_policy_t *policy,
                        knot_update_serial_t soa_up, bool force)
{
	assert(zone);
	assert(config);
	assert(zone_keys);
	assert(policy);

	// Read zone keys from disk
	bool nsec3_enabled = knot_is_nsec3_enabled(zone);
	int result = knot_load_zone_keys(config->dnssec_keydir,
	                                 zone->apex->owner,
	                                 nsec3_enabled, zone_keys);
	if (result != KNOT_EOK) {
		log_zone_error(zone->apex->owner, "DNSSEC, failed to load keys (%s)",
		               knot_strerror(result));
		knot_free_zone_keys(zone_keys);
		return result;
	}

	// Init sign policy
	knot_dnssec_init_default_policy(policy);
	policy->soa_up = soa_up;
	policy->forced_sign = force;

	// Override signature lifetime, if set in config
	if (config->sig_lifetime > 0) {
		knot_dnssec_policy_set_sign_lifetime(policy, config->sig_lifetime);
	}

	return KNOT_EOK;
}

int dnssec_zone_sign(zone_update_t *up, uint32_t *refresh_at)
{
	return zone_sign(up, up->zone->flags & ZONE_FORCE_RESIGN, refresh_at);
}

