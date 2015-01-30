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
 * \file contents.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone contents structure and API for manipulating it.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include "knot/zone/node.h"
#include "knot/zone/zone-tree.h"

/*----------------------------------------------------------------------------*/

typedef struct zone_contents {
	zone_node_t *apex;       /*!< Apex node of the zone (holding SOA) */

	zone_tree_t *nodes;
	zone_tree_t *nsec3_nodes;
	mm_ctx_t mm;
} zone_contents_t;

/*----------------------------------------------------------------------------*/

/* ------------------- TO ANSWERING ------------------------------------ */

int zone_contents_find_dname(const zone_contents_t *contents,
                             const knot_dname_t *name,
                             const zone_node_t **node,
                             const zone_node_t **closest_encloser,
                             const zone_node_t **previous);

const zone_node_t *zone_contents_find_previous(const zone_contents_t *contents,
                                               const knot_dname_t *name);

int zone_contents_find_nsec3_for_name(const zone_contents_t *contents,
                                      const knot_dname_t *name,
                                      const zone_node_t **nsec3_node,
                                      const zone_node_t **nsec3_previous);

/* ------------------- TO ANSWERING ------------------------------------ */

int zone_contents_shallow_copy(const zone_contents_t *from, zone_contents_t **to);

void zone_contents_free(zone_contents_t **contents);

void zone_contents_deep_free(zone_contents_t **contents);

/*! \brief Return zone SOA rdataset. */
const knot_rdataset_t *zone_contents_soa(const zone_contents_t *zone);

/*!
 * \brief Fetch zone serial.
 *
 * \param zone Zone.
 *
 * \return serial or 0
 */
uint32_t zone_contents_serial(const zone_contents_t *zone);

/*! \brief Calculate next serial. */
uint32_t zone_contents_next_serial(const zone_contents_t *zone, int policy);

/*!
 * \brief Return true if zone is signed.
 */
bool zone_contents_is_signed(const zone_contents_t *zone);

/*!
 * \brief Return true if zone is empty.
 */
bool zone_contents_is_empty(const zone_contents_t *zone);

/* --------------------------- NEW API -------------------------------------- */

zone_contents_t *zone_contents_new(const knot_dname_t *apex_name);

zone_node_t *zone_contents_find_node_for_type(zone_contents_t *zone, const knot_dname_t *owner, const uint16_t type);

int zone_contents_add_rr(zone_contents_t *z, const knot_rrset_t *rr, zone_node_t **n);

const zone_node_t *zone_contents_find_wildcard_child(const zone_contents_t *contents,
                                                     const zone_node_t *parent);

/*! @} */
