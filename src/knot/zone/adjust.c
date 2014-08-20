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

#include <assert.h>

#include "common-knot/hattrie/hat-trie.h"
#include "knot/zone/adjust.h"

struct adjust_walker {
	hattrie_iter_t *itt;
	zone_node_t *prev;
	zone_node_t *curr;
};

static int walker_init(struct adjust_walker *walk, hattrie_t *t, bool sorted)
{
	walk->itt = hattrie_iter_begin(t, sorted);
	if (walk->itt == NULL) {
		return KNOT_ENOMEM;
	}
	
	walk->curr = NULL;
	walk->prev = NULL;
	
	return KNOT_EOK;
}

static void walker_next(struct adjust_walker *walk)
{
	if (walk->curr && !hattrie_iter_finished(walk->itt)) {
		hattrie_iter_next(walk->itt);
	}
	
	walk->prev = walk->curr;
	walk->curr = (zone_node_t *)*hattrie_iter_val(walk->itt);
}

static bool walker_finished(struct adjust_walker *walk)
{
	return walk->curr && hattrie_iter_finished(walk->itt);
}

static void adjust_node_flags(zone_node_t *n)
{
	return;
}

static void adjust_node_deletion(zone_tree_t *t, const zone_node_t *n)
{
	zone_node_t *found = NULL;
	zone_tree_get(t, n->owner, &found);
	if (found) {
		adjust_node_flags(found);
		// Node stays, nothing more to fix
		return;
	}
	
	zone_node_t *prev = NULL;
	zone_tree_get_less_or_equal(t, n->owner, &found, &prev);
	zone_node_t *next = zone_tree_get_next(t, n->owner);
	assert(prev && next);
	
	next->prev = prev;
}

static void adjust_node_addition(zone_tree_t *t, const zone_node_t *n)
{
	zone_node_t *found = NULL;
	zone_node_t *prev = NULL;
	zone_tree_get_less_or_equal(t, n->owner, &found, &prev);
	zone_node_t *next = zone_tree_get_next(t, n->owner);
	assert(prev && next);
	assert(knot_dname_is_equal(found->owner, n->owner));
	
	next->prev = found;
	
	adjust_node_flags(found);
}

static int apply_to_tree(zone_tree_t *t_walk, zone_tree_t *t_find,
                         void (*f)(zone_tree_t *, const zone_node_t *))
{
	struct adjust_walker walk;
	int ret = walker_init(&walk, t_walk, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	while (!walker_finished(&walk)) {
		walker_next(&walk);
		f(t_find, walk.curr);
	}
	
	return KNOT_EOK;
}

static int apply_to_part(const zone_contents_t *part, zone_contents_t *zone,
                         void (*f)(zone_tree_t *, const zone_node_t *))
{
	int ret = apply_to_tree(part->nodes, zone->nodes, f);
	if (part->nsec3_nodes && ret == KNOT_EOK) {
		if (zone->nsec3_nodes == NULL) {
			//TODO: adjust full NSEC3
		}
		ret = apply_to_tree(part->nsec3_nodes, zone->nsec3_nodes, f);
	}
	
	return ret;
}

static int partial_adjust(zone_contents_t *zone, const changeset_t *ch)
{
	int ret = apply_to_part(ch->remove, zone, adjust_node_deletion);
	if (ret == KNOT_EOK) {
		ret = apply_to_part(ch->add, zone, adjust_node_addition);
	}
	
	return ret;
}

static int full_adjust(zone_contents_t *zone)
{
	
	return KNOT_EOK;
}

/* ------------------------------- API -------------------------------------- */

int zone_adjust(zone_update_t *up)
{
	if (up->change) {
		return partial_adjust(up->zone, up->change);
	} else {
		return full_adjust(up->zone);
	}
}

