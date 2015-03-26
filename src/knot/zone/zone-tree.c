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

#include <assert.h>

#include "knot/zone/zone-tree.h"
#include "libknot/errcode.h"
#include "libknot/internal/macros.h"
#include "libknot/internal/namedb/namedb_lmdb.h"
#include "libknot/internal/namedb/namedb_trie.h"

enum get_op {
	GET_EQ,
	GET_PREV,
	GET_NEXT
};

static namedb_val_t fill_db_val(const knot_dname_t *dname, uint8_t *data)
{
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, dname, NULL);
	namedb_val_t val = { .data = lf + 1, .len = *lf };
	return val;
}

static zone_node_t *val_to_node(const namedb_val_t *val)
{
	if (val == NULL) {
		return NULL;
	}

	return (zone_node_t *)(val->data);
}

int zone_tree_init(zone_tree_t *tree, const namedb_api_t *api, mm_ctx_t *mm)
{
	if (api == NULL) {
		return KNOT_EINVAL;
	}

	tree->api = api;
	return api->init(&tree->db, NULL, mm);
}

size_t zone_tree_weight(const zone_tree_t* tree)
{
	namedb_txn_t tx;
	tree->api->txn_begin(tree->db, &tx, NAMEDB_RDONLY);
	size_t weight = tree->api->count(&tx);
	tree->api->txn_abort(&tx);
	return weight;
}

bool zone_tree_is_empty(const zone_tree_t *tree)
{
	return zone_tree_weight(tree) == 0;
}

int zone_tree_insert(zone_tree_t *tree, zone_node_t *node)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	namedb_txn_t tx;
	int ret = tree->api->txn_begin(tree, &tx, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(tree && node && node->owner);
	uint8_t lf[KNOT_DNAME_MAXLEN];

	namedb_val_t key = fill_db_val(node->owner, lf);
	namedb_val_t val = { .data = node, .len = sizeof(node) };

	ret = tree->api->insert(&tx, &key, &val, 0);
	if (ret != KNOT_EOK) {
		tree->api->txn_abort(&tx);
		return ret;
	}

	return tree->api->txn_commit(&tx);
}

static zone_node_t *get_node(zone_tree_t *tree, const knot_dname_t *owner, unsigned op)
{
	if (owner == NULL) {
		return NULL;
	}

	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, owner, NULL);
	if (op == NAMEDB_LEQ && tree->api == namedb_trie_api()) {
		lf[*lf - 1]--;
	}

	namedb_val_t key = { .data = lf + 1, .len = *lf };
	namedb_val_t val = { '\0' };

	namedb_txn_t tx;
	int ret = tree->api->txn_begin(tree, &tx, NAMEDB_RDONLY);
	if (ret != KNOT_EOK) {
		return NULL;
	}
	ret = tree->api->find(&tx, &key, &val, op);
	tree->api->txn_abort(&tx);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	return val_to_node(&val);
}

zone_node_t *zone_tree_get(zone_tree_t *tree, const knot_dname_t *owner)
{
	return get_node(tree, owner, 0);
}

zone_node_t *zone_tree_get_next(zone_tree_t *tree, const knot_dname_t *owner)
{
	zone_node_t *n = get_node(tree, owner, NAMEDB_NEXT);
	if (n) {
		return n;
	}

	return get_node(tree, owner, NAMEDB_FIRST);
}

zone_node_t *zone_tree_get_prev(zone_tree_t *tree, const knot_dname_t *owner)
{
	if (tree->api == namedb_trie_api()) {
		const size_t size = knot_dname_size(owner);
		knot_dname_t less[size];
		memcpy(less, owner, size);
		less[size - 1] -= 1;
		owner = less;
	} else {
		// Only trie supported.
		assert(0);
	}

	zone_node_t *n = get_node(tree, owner, NAMEDB_LEQ);
	if (n) {
		return n;
	}

	return get_node(tree, owner, NAMEDB_LAST);
}

int zone_tree_remove(zone_tree_t *tree,
                     const knot_dname_t *owner,
                     zone_node_t **removed)
{
	if (owner == NULL) {
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
		return KNOT_ENONODE;
	}

	zone_node_t *to_remove = zone_tree_get(tree, owner);
	if (to_remove == NULL) {
		return KNOT_ENOENT;
	} else {
		*removed = to_remove;
	}

	// We have entry to delete.
	namedb_txn_t tx;
	tree->api->txn_begin(tree, &tx, 0);

	uint8_t lf[KNOT_DNAME_MAXLEN];
	namedb_val_t key = fill_db_val(owner, lf);
	int ret =  tree->api->del(&tx, &key);
	if (ret != KNOT_EOK) {
		tree->api->txn_abort(&tx);
		return ret;
	}

	return tree->api->txn_commit(&tx);
}

void zone_tree_clear(zone_tree_t *tree)
{
	if (tree) {
		tree->api->deinit(tree->db);
		tree->api = NULL;
		tree->db = NULL;
	}
}

static zone_node_t *get_node_from(namedb_iter_t *iter, const namedb_api_t *api)
{
	namedb_val_t val;
	int ret = api->iter_val(iter, &val);
	if (ret == KNOT_EOK) {
		return val.data;
	} else {
		return NULL;
	}
}

int zone_tree_apply(zone_tree_t *tree, ztree_cb_t *cb, void *data, bool sorted)
{
	if (tree == NULL || cb == NULL) {
		return KNOT_EINVAL;
	}

	namedb_txn_t tx;
	int ret = tree->api->txn_begin(tree->db, &tx, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	namedb_iter_t *it = tree->api->iter_begin(&tx, sorted ? NAMEDB_SORTED : 0);
	if (it == NULL) {
		tree->api->txn_abort(&tx);
		return KNOT_ENOMEM;
	}

	zone_node_t *node = get_node_from(it, tree->api);
	while (node) {
		int ret = cb(node, data);
		if (ret == KNOT_EOK) {
			tree->api->iter_next(it);
		}

		if (ret != KNOT_EOK) {
			tree->api->txn_abort(&tx);
			tree->api->iter_finish(it);
			return ret;
		}
		node = get_node_from(it, tree->api);
	}

	return KNOT_EOK;
}

