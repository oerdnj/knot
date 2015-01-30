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

#include <urcu.h>

#include "knot/updates/zone-lock.h"

int zone_lock_init(zone_lock_t *l, const lock_type_t type)
{
	l->type = type;
	if (type == LOCK_RCU) {
		l->context = NULL;
	} else {
		l->context = malloc(sizeof(pthread_mutex_t));
		if (l->context == NULL) {
			return KNOT_ERROR;
		}
		int ret = pthread_mutex_init(l->context, NULL);
		if (ret != 0) {
			free(l->context);
			return KNOT_ERROR;
		}
	}

	return KNOT_EOK;
}

void zone_lock(zone_lock_t *l)
{
	UNUSED(l);
	rcu_read_lock();
}

void zone_unlock(zone_lock_t *l)
{
	UNUSED(l);
	rcu_read_unlock();
}

void zone_synchronize(zone_lock_t *l)
{
	UNUSED(l);
	synchronize_rcu();
}
