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

/*!
 * \file semantic-check.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief DNS node semantic checks.
 *
 * @{
 */

#pragma once

#include "knot/zone/node.h"
#include "knot/updates/zone-update.h"

int sem_check_node(zone_update_t *up, const zone_node_t *node);

/*! @} */
