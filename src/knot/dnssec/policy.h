/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/conf/conf.h"
#include "knot/dnssec/context.h"
#include "knot/zone/contents.h"

/*!
 * \brief Update policy parameters depending on zone content.
 */
void update_policy_from_zone(dnssec_kasp_policy_t *policy,
                             const zone_contents_t *zone);

/*!
 * \brief Set default DNSSEC policy for zone without assigned policy.
 */
void set_default_policy(dnssec_kasp_policy_t *policy, const conf_zone_t *config,
                        const zone_contents_t *zone);
