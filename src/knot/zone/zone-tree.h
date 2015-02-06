/*!
 * \file zone-tree.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone tree structure and API for manipulating it.
 * @{
 */

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

#pragma once

#include "libknot/internal/namedb/namedb.h"
#include "knot/zone/node.h"

/*----------------------------------------------------------------------------*/

typedef struct zone_tree {
	namedb_api_t *api;
	namedb_t *db;
} zone_tree_t;

zone_tree_t *zone_tree_create(const namedb_api_t *api, mm_ctx_t *mm);

/*!
 * \brief Return weight of the zone tree (number of nodes).
 * \param tree Zone tree.
 * \return number of nodes in tree.
 */
size_t zone_tree_weight(const zone_tree_t* tree);

/*!
 * \brief Checks if the zone tree is empty.
 *
 * \param tree Zone tree to check.
 *
 * \return Nonzero if the zone tree is empty.
 */
bool zone_tree_is_empty(const zone_tree_t *tree);

/*!
 * \brief Inserts the given node into the zone tree.
 *
 * \param tree Zone tree to insert the node into.
 * \param node Node to insert.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int zone_tree_insert(zone_tree_t *tree, zone_node_t *node);

zone_node_t *zone_tree_get(zone_tree_t *tree, const knot_dname_t *owner);

zone_node_t *zone_tree_get_next(zone_tree_t *tree,
                                const knot_dname_t *owner);

zone_node_t *zone_tree_get_prev(zone_tree_t *tree,
                                const knot_dname_t *owner);

/*!
 * \brief Removes node with the given owner from the zone tree and returns it.
 *
 * \param tree Zone tree to remove the node from.
 * \param owner Owner of the node to find.
 * \param removed The removed node.
 *
 * \retval The removed node.
 */
int zone_tree_remove(zone_tree_t *tree,
                     const knot_dname_t *owner,
                     zone_node_t **removed);

/*!
 * \brief Destroys the zone tree, not touching the saved data.
 *
 * \param tree Zone tree to be destroyed.
 */
void zone_tree_free(zone_tree_t **tree);

/*!
 * \brief Destroys the zone tree, together with the saved data.
 *
 * \param tree Zone tree to be destroyed.
 * \param free_owners Set to <> 0 if owners of the nodes should be destroyed
 *                    as well. Set to 0 otherwise.
 */
void zone_tree_deep_free(zone_tree_t **tree);

/*----------------------------------------------------------------------------*/

/*! @} */
