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

#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>

#include "knot/updates/changesets.h"
#include "libknot/rrset.h"
#include "libknot/errcode.h"
#include "libknot/internal/macros.h"

/* -------------------- Changeset iterator helpers -------------------------- */

/*! \brief Adds RRSet to given zone. */
static int add_rr_to_zone(zone_contents_t *z, knot_rrset_t **soa, const knot_rrset_t *rrset)
{
	if (rrset->type == KNOT_RRTYPE_SOA) {
		if (*soa == NULL) {
			*soa = knot_rrset_copy(rrset, NULL);
			if (*soa == NULL) {
				return KNOT_ENOMEM;
			}
		}
		// Do not add SOAs into actual contents.
		return KNOT_EOK;
	}

	return zone_contents_add_rr(z, rrset);
}

static zone_node_t *get_node(namedb_iter_t *iter, const namedb_api_t *api)
{
	namedb_val_t val;
	int ret = api->iter_val(iter, &val);
	if (ret == KNOT_EOK) {
		return val.data;
	} else {
		return NULL;
	}
}

static bool iter_finished(namedb_iter_t *it, const namedb_api_t *api)
{
	return get_node(it, api) == NULL;
}

struct part_iter {
	namedb_txn_t *tx;
	namedb_t *iter;
	const namedb_api_t *api;
};

static struct part_iter *create_iter_part_from(const namedb_api_t *api, namedb_t *db, bool sorted)
{
	struct part_iter *part = malloc(sizeof(*part));
	if (part) {
		part->api = api;
		int ret = api->txn_begin(db, part->tx, NAMEDB_RDONLY);
		if (ret != KNOT_EOK) {
			free(part);
			return NULL;
		}
		part->iter = api->iter_begin(part->tx, sorted ? NAMEDB_SORTED : 0);
	}

	return part;
}

static void free_iter_part(struct part_iter *part)
{
	part->api->iter_finish(part->iter);
	part->api->txn_abort(part->tx);
	free(part);
}

/*! \brief Cleans up trie iterations. */
static void cleanup_iter_list(list_t *l)
{
	ptrnode_t *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, *l) {
		struct part_iter *p = (struct part_iter *)n->d;
		free_iter_part(p);
		rem_node(&n->n);
		free(n);
	}
	init_list(l);
}


/*! \brief Inits changeset iterator with given name_dbs. */
static int changeset_iter_init(changeset_iter_t *ch_it, const namedb_api_t *api,
                               bool sorted, size_t tries, ...)
{
	memset(ch_it, 0, sizeof(*ch_it));
	init_list(&ch_it->iters);

	va_list args;
	va_start(args, tries);

	for (size_t i = 0; i < tries; ++i) {
		namedb_t *db = va_arg(args, namedb_t *);
		if (db) {
			struct part_iter *p = create_iter_part_from(api, db, sorted);
			if (p == NULL) {
				return KNOT_ENOMEM;
			}
			if (ptrlist_add(&ch_it->iters, p, NULL) == NULL) {
				free_iter_part(p);
				cleanup_iter_list(&ch_it->iters);
				return KNOT_ENOMEM;
			}
		}
	}

	va_end(args);

	return KNOT_EOK;
}

/*! \brief Gets next node from trie iterators. */
static void iter_next_node(changeset_iter_t * ch_it, namedb_iter_t *db_it)
{
	// Get next node, but not for the very first call.
	if (ch_it->node) {
		ch_it->api->iter_next(db_it);
	}

	if (iter_finished(db_it, ch_it->api)) {
		ch_it->node = NULL;
		return;
	}

	ch_it->node = get_node(db_it, ch_it->api);
	assert(ch_it->node);
	while (ch_it->node && ch_it->node->rrset_count == 0) {
		// Skip empty non-terminals.
		ch_it->api->iter_next(db_it);
		ch_it->node = get_node(db_it, ch_it->api);
	}

	ch_it->node_pos = 0;
}

/*! \brief Gets next RRSet from trie iterators. */
static knot_rrset_t get_next_rr(changeset_iter_t *ch_it, namedb_iter_t *db_it)
{
	if (ch_it->node == NULL || ch_it->node_pos == ch_it->node->rrset_count) {
		iter_next_node(ch_it, db_it);
		if (ch_it->node == NULL) {
			assert(iter_finished(db_it, ch_it->api));
			knot_rrset_t rr;
			knot_rrset_init_empty(&rr);
			return rr;
		}
	}

	return node_rrset_at(ch_it->node, ch_it->node_pos++);
}

static bool need_to_insert(zone_contents_t *counterpart, const knot_rrset_t *rr)
{
	zone_node_t *node = zone_contents_find_node_for_rr(counterpart, rr);
	if (node == NULL) {
		return true;
	}

	if (!node_rrtype_exists(node, rr->type)) {
		return true;
	}

	knot_rrset_t node_rr = node_rrset(node, rr->type);
	if (!knot_rrset_equal(rr, &node_rr, KNOT_RRSET_COMPARE_WHOLE)) {
		return true;
	}

	// Clear the data from the other part of the changeset.
	knot_rdataset_t *to_free = node_rdataset(node, rr->type);
	assert(to_free);
	node_remove_rdataset(node, rr->type);
	knot_rdataset_clear(to_free, &counterpart->mm);

	if (node->rrset_count == 0) {
		zone_tree_t *t = zone_contents_rrset_is_nsec3rel(rr) ? counterpart->nsec3_nodes :
		                                                       counterpart->nodes;
		zone_contents_delete_empty_node(counterpart, t, node);
	}

	return false;
}

/* ------------------------------- API -------------------------------------- */

int changeset_init(changeset_t *ch, const knot_dname_t *apex)
{
	memset(ch, 0, sizeof(changeset_t));

	// Init local changes
	ch->add = zone_contents_new(apex);
	if (ch->add == NULL) {
		return KNOT_ENOMEM;
	}
	ch->remove = zone_contents_new(apex);
	if (ch->remove == NULL) {
		zone_contents_free(&ch->add);
		return KNOT_ENOMEM;
	}

	// Init change lists
	init_list(&ch->new_data);
	init_list(&ch->old_data);

	return KNOT_EOK;
}

changeset_t *changeset_new(const knot_dname_t *apex)
{
	changeset_t *ret = malloc(sizeof(changeset_t));
	if (ret == NULL) {
		return NULL;
	}

	if (changeset_init(ret, apex) == KNOT_EOK) {
		return ret;
	} else {
		free(ret);
		return NULL;
	}
}

bool changeset_empty(const changeset_t *ch)
{
	if (ch == NULL || ch->add == NULL || ch->remove == NULL) {
		return true;
	}

	if (ch->soa_to) {
		return false;
	}

	changeset_iter_t itt;
	changeset_iter_all(&itt, ch, false);

	knot_rrset_t rr = changeset_iter_next(&itt);
	changeset_iter_clear(&itt);

	return knot_rrset_empty(&rr);
}

size_t changeset_size(const changeset_t *ch)
{
	if (ch == NULL) {
		return 0;
	}

	changeset_iter_t itt;
	changeset_iter_all(&itt, ch, false);

	size_t size = 0;
	knot_rrset_t rr = changeset_iter_next(&itt);
	while(!knot_rrset_empty(&rr)) {
		++size;
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	if (!knot_rrset_empty(ch->soa_from)) {
		size += 1;
	}
	if (!knot_rrset_empty(ch->soa_to)) {
		size += 1;
	}

	return size;
}

int changeset_add_rrset(changeset_t *ch, const knot_rrset_t *rrset)
{
	if (need_to_insert(ch->remove, rrset)) {
		return add_rr_to_zone(ch->add, &ch->soa_to, rrset);
	} else {
		return KNOT_EOK;
	}
}

int changeset_rem_rrset(changeset_t *ch, const knot_rrset_t *rrset)
{
	if (need_to_insert(ch->add, rrset)) {
		return add_rr_to_zone(ch->remove, &ch->soa_from, rrset);
	} else {
		return KNOT_EOK;
	}
}

void changeset_clear(changeset_t *ch)
{
	if (ch == NULL) {
		return;
	}

	zone_contents_deep_free(&ch->add);
	zone_contents_deep_free(&ch->remove);

	knot_rrset_free(&ch->soa_from, NULL);
	knot_rrset_free(&ch->soa_to, NULL);
}

void changeset_free(changeset_t *ch)
{
	changeset_clear(ch);
	free(ch);
}

int changeset_iter_add(changeset_iter_t *itt, const changeset_t *ch, bool sorted)
{
	return changeset_iter_init(itt, ch->add->nodes->api, sorted, 2,
	                           ch->add->nodes, ch->add->nsec3_nodes);
}

int changeset_iter_rem(changeset_iter_t *itt, const changeset_t *ch, bool sorted)
{
	return changeset_iter_init(itt, ch->add->nodes->api, sorted, 2,
	                           ch->remove->nodes, ch->remove->nsec3_nodes);
}

int changeset_iter_all(changeset_iter_t *itt, const changeset_t *ch, bool sorted)
{
	return changeset_iter_init(itt, ch->add->nodes->api, sorted, 4,
	                           ch->add->nodes, ch->add->nsec3_nodes,
	                           ch->remove->nodes, ch->remove->nsec3_nodes);
}

knot_rrset_t changeset_iter_next(changeset_iter_t *it)
{
	assert(it);
	ptrnode_t *n = NULL;
	knot_rrset_t rr;
	knot_rrset_init_empty(&rr);
	WALK_LIST(n, it->iters) {
		namedb_iter_t *db_it = (namedb_iter_t *)n->d;
		if (iter_finished(db_it, it->api)) {
			continue;
		}

		rr = get_next_rr(it, db_it);
		if (!knot_rrset_empty(&rr)) {
			// Got valid RRSet.
			return rr;
		}
	}

	return rr;
}

void changeset_iter_clear(changeset_iter_t *it)
{
	if (it) {
		cleanup_iter_list(&it->iters);
		it->node = NULL;
		it->node_pos = 0;
	}
}

