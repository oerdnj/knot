/*!
 * \file zone_update.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief API for updating zone and quering zone that is being updated.
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

#include "knot/updates/changesets.h"
#include "knot/zone/zone.h"
#include "knot/zone/contents.h"
#include "libknot/internal/mempattern.h"

typedef struct {
	zone_t *zone;        /*!< Zone being updated. */
	zone_contents_t *new_cont; /*!< New zone contents for full updates. */
	zone_contents_t *synth_nodes; /*!< Cache for synthesised nodes. */
	changeset_t change;          /*!< Changes we want to apply. */
	mm_ctx_t mm;                  /*!< Memory context used for intermediate nodes. */
	changeset_t iteration_changes;
	uint8_t flags;
} zone_update_t;

typedef struct {
	zone_update_t *up;
	hattrie_iter_t *t_it;
	hattrie_iter_t *ch_it;
	const zone_node_t *t_node;
	const zone_node_t *ch_node;
	const zone_node_t *next_n;
	bool nsec3;
} zone_update_iter_t;

typedef enum {
	UPDATE_FULL = 1 << 0,
	UPDATE_INCREMENTAL = 1 << 1,
	UPDATE_SIGN = 1 << 2,
	UPDATE_DIFF = 1 << 3,
	UPDATE_REPLACE_CNAMES = 1 << 4,
	UPDATE_WRITING_ITER = 1 << 5
} zone_update_flags_t;

/*!
 * \brief Inits given zone update structure, new memory context is created.
 *
 * \param update  Zone update structure to init.
 * \param zone    Init with this zone.
 */
int zone_update_init(zone_update_t *update, zone_t *zone, zone_update_flags_t flags);

/*!
 * \brief Returns node that would be in the zone after updating it.
 *
 * \note Returned node is either zone original or synthesized, do *not* free
 *       or modify. Node's data are guaranteed to be valid at least between
 *       two subsequent get operations and during whole update iteration. If
 *       you need persistent nodes, a copy must be made.
 *
 * \param update  Zone update.
 * \param dname   Dname to search for.
 *
 * \return Node after zone update.
 */
const zone_node_t *zone_update_get_node(zone_update_t *update, const knot_dname_t *dname,
                                        const uint16_t type);
const zone_node_t *zone_update_get_prev(zone_update_t *update, const knot_dname_t *dname, const uint16_t type);
const zone_node_t *zone_update_get_apex(zone_update_t *update);
bool zone_update_has_children(zone_update_t *update, const knot_dname_t *owner);
bool zone_update_node_is_nonauth(zone_update_t *update, const knot_dname_t *owner);
uint32_t zone_update_current_serial(zone_update_t *update);

const knot_rdataset_t *zone_update_from(zone_update_t *update);
const knot_rdataset_t *zone_update_to(zone_update_t *update);

/*!
 * \brief Clear data allocated by given zone update structure.
 *
 * \param  update Zone update to clear.
 */
void zone_update_clear(zone_update_t *update);

int zone_update_add(zone_update_t *update, const knot_rrset_t *rrset);
int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset);
int zone_update_commit(zone_update_t *update);

int zone_update_iter(zone_update_iter_t *it, zone_update_t *update, const bool read_only);
int zone_update_iter_nsec3(zone_update_iter_t *it, zone_update_t *update, const bool read_only);
int zone_update_iter_next(zone_update_iter_t *it);
const zone_node_t *zone_update_iter_val(zone_update_iter_t *it);
int zone_update_iter_finish(zone_update_iter_t *it);
int zone_update_load_contents(zone_update_t *up);
bool zone_update_no_change(zone_update_t *up);

/*! @} */
