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
/*!
 * \file zone-events.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief DNSSEC operations triggered on zone events.
 *
 * \addtogroup dnssec
 * @{
 */
#pragma once

#include "knot/zone/zone.h"
#include "knot/updates/zone-update.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/dnssec/policy.h"

/*!
 * \brief init_dnssec_structs
 * \param zone
 * \param config
 * \param zone_keys
 * \param policy
 * \param soa_up
 * \param force
 * \return 
 */
int init_dnssec_structs(const zone_contents_t *zone,
                        const conf_zone_t *config,
                        knot_zone_keys_t *zone_keys,
                        knot_dnssec_policy_t *policy,
                        knot_update_serial_t soa_up, bool force);

/*!
 * \brief DNSSEC resign zone, store new records into changeset. Valid signatures
 *        and NSEC(3) records will not be changed.
 *
 * \param zone         Zone contents to be signed.
 * \param zone_config  Zone/DNSSEC configuration.
 * \param out_ch       New records will be added to this changeset.
 * \param soa_up       SOA serial update policy.
 * \param refresh_at   Signature refresh time of the oldest signature in zone.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_zone_sign(zone_update_t *up, uint32_t *refresh_at);

/*! @} */
