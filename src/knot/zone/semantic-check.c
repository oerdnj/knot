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

#include <stdlib.h>
#include <assert.h>

#include "knot/zone/semantic-check.h"
#include "knot/updates/zone-update.h"


#define CHECK_COUNT (SEMCHECK_LAST)

static const char *error_messages[CHECK_COUNT] = {
	[TTL_MISMATCH] = "RRSet TTLs mismatched",
	[CNAME_EXTRA_RECORDS] = "CNAME, node contains other records",
	[CNAME_MULTIPLE] = "CNAME, multiple records",
};

void log_semantic_error(const knot_dname_t *zone_name,
                        const knot_dname_t *node_name,
                        semcheck_err_t error)
{
	char name[KNOT_DNAME_MAXLEN];
	knot_dname_to_str(name, node_name, sizeof(name));
	log_zone_error(zone_name, "semantic check, node '%s' (%s)",
	               node_name, error_messages[error]);
}

void log_semantic_warning(const knot_dname_t *zone_name,
                          const knot_dname_t *node_name,
                          semcheck_err_t error)
{
	char name[KNOT_DNAME_MAXLEN];
	knot_dname_to_str(name, node_name, sizeof(name));
	log_zone_warning(zone_name, "semantic check, node '%s' (%s)",
	                 node_name, error_messages[error]);
}

static bool only_dnssec(const zone_node_t *node)
{
	return ((node_rrtype_exists(node, KNOT_RRTYPE_NSEC) ||
	        node_rrtype_exists(node, KNOT_RRTYPE_RRSIG)) &&
	        node->rrset_count <= 3);
}

static bool cname_check(const knot_dname_t *zone_name,
                        const zone_node_t *node)
{
	const knot_rdataset_t *cname_rrs = node_rdataset(node, KNOT_RRTYPE_CNAME);
	if (cname_rrs == NULL) {
		return true;
	}

	if (node->rrset_count > 1 && !only_dnssec(node)) {
		/* With DNSSEC node can contain RRSIGs or NSEC */
		log_semantic_error(zone_name, node->owner, CNAME_EXTRA_RECORDS);
		return false;
	}

	if (cname_rrs->rr_count > 1) {
		log_semantic_error(zone_name, node->owner, CNAME_MULTIPLE);
		return false;
	}

	return true;
}

bool sem_check_node(zone_update_t *up, const zone_node_t *node)
{
	return cname_check(up->zone->name, node);
}

