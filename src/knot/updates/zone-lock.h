/*!
 * \file zone_lock.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief API for generic zone contents locking.
 *
 * \addtogroup server
 * @{
 */
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

#pragma once

typedef enum {
	ZLOCK_RCU = 0,
	ZLOCK_RW = 1,
	ZLOCK_NONE = 2
} lock_type_t;

typedef struct zone_lock {
	void *context;
	lock_type_t type;
} zone_lock_t;

int zone_lock_init(zone_lock_t *l, const lock_type_t type);
void zone_lock(zone_lock_t *l);
void zone_unlock(zone_lock_t *l);
void zone_synchronize(zone_lock_t *l);

/*! @} */

