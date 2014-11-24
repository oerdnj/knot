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

#include "knot/common/log.h"
#include "knot/server/journal.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/contents.h"
#include "knot/zone/zonefile.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/apply.h"
#include "libknot/rdata.h"

/*! \brief Check zone configuration constraints. */
void zone_set_payload(zone_t *zone)
{
	/* Bootstrapped zone, no checks apply. */
	if (zone->contents == NULL) {
		return;
	}

	/* Check minimum EDNS0 payload if signed. (RFC4035/sec. 3) */
	if (zone_contents_is_signed(zone->contents)) {
		if (conf()->max_udp_payload < KNOT_EDNS_MIN_DNSSEC_PAYLOAD) {
			log_zone_warning(zone->name, "EDNS payload size is "
			                 "lower than %u bytes for DNSSEC zone",
					 KNOT_EDNS_MIN_DNSSEC_PAYLOAD);
			conf()->max_udp_payload = KNOT_EDNS_MIN_DNSSEC_PAYLOAD;
		}
	}
}


bool zone_load_can_bootstrap(const conf_zone_t *zone_config)
{
	return zone_config && !EMPTY_LIST(zone_config->acl.xfr_in);
}

