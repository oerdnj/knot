\/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/updates/changesets.h"

enum zone_sign_flags {
	ZONE_SIGN_NONE = 0,
	ZONE_SIGN_DROP_SIGNATURES = (1 << 0),
	ZONE_SIGN_KEEP_SOA_SERIAL = (1 << 1),
};

typedef enum zone_sign_flags zone_sign_flags_t;

int dnssec_zone_sign(zone_update_t *up, uint32_t *refresh_at);

/*! @} */
