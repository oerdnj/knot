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

#include "knot/conf/conf.h"
#include "knot/server/journal.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone.h"

/*!
 * \brief Load zone contents according to the configuration.
 *
 * \param conf
 * \param zone_name
 * \return new zone contents or NULL
 */
zone_contents_t *zone_load_contents(conf_t *conf, const knot_dname_t *zone_name);

/*!
 * \brief Check loaded zone contents validity.
 *
 * \param conf
 * \param contents
 * \return KNOT_EOK or an error
 */
int zone_load_check(conf_t *conf, zone_contents_t *contents);

/*!
 * \brief Update zone contents from the journal.
 *
 * \param conf
 * \param zone
 * \param contents
 * \return KNOT_EOK or an error
 */
int zone_load_journal(conf_t *conf, zone_t *zone, zone_contents_t *contents);

/*!
 * \brief Zone loading post-actions (zone resign, calculation of delta)
 *
 * \param conf
 * \param contents
 * \param zone
 * \param dnssec_refresh
 * \return KNOT_EOK or an error
 */
int zone_load_post(conf_t *conf, zone_contents_t *contents, zone_t *zone,
                   uint32_t *dnssec_refresh);

/*!
 * \brief Check if zone can be bootstrapped.
 *
 * \param conf
 * \param zone_name
 */
bool zone_load_can_bootstrap(conf_t *conf, const knot_dname_t *zone_name);
