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
#include "libknot/internal/macros.h"
#include "libknot/internal/namedb/namedb_lmdb.h"
#include "libknot/internal/namedb/namedb_trie.h"

enum get_op {
	GET_EQ,
	GET_PREV,
	GET_NEXT
};

#define CLEANUP(f) __attribute__ ((__cleanup__(f)))

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
	return api->init(NULL, &tree->db, mm);
}

size_t zone_tree_weight(const zone_tree_t* tree)
{
	namedb_txn_t tx CLEANUP(tree->api->txn_abort);
	tree->api->txn_begin(tree, &tx, NAMEDB_RDONLY);
	return tree->api->count(&tx);
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

	namedb_txn_t tx CLEANUP(tree->api->txn_commit);
	tree->api->txn_begin(tree, &tx, 0);

	assert(tree && node && node->owner);
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, node->owner, NULL);

	namedb_val_t key = { .data = lf + 1, .len = *lf };
	namedb_val_t val = { .data = node, .len = sizeof(node); };

	return tree->api->insert(&tx, &key, &val, 0);
}

static zone_node_t *get_node(zone_tree_t *tree, const knot_dname_t *owner, unsigned op)
{
	if (owner == NULL) {
		return NULL;
	}

	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, owner, NULL);
	if (op == NAMEDB_LEQ) {
#warning this will only work with trie
		lf[*lf - 1]--;
	}

	namedb_val_t key = { .data = lf + 1, .size = *lf };
	namedb_val_t val = { '\0' };

	namedb_txn_t tx CLEANUP(tree->api->txn_abort);
	tree->api->txn_begin(tree, &tx, 0);
	int ret = tree->api->find(&tx, &key, &val, op);
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
#warning sort this out
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

	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, owner, NULL);

	value_t *rval = hattrie_tryget(tree, (char*)lf+1, *lf);
	if (rval == NULL) {
		return KNOT_ENOENT;
	} else {
		*removed = (zone_node_t *)(*rval);
	}


	hattrie_del(tree, (char*)lf+1, *lf);
	return KNOT_EOK;
}

int zone_tree_apply_inorder(zone_tree_t *tree,
                            zone_tree_apply_cb_t function,
                            void *data)
{
	if (function == NULL) {
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
		return KNOT_EOK;
	}

	int result = KNOT_EOK;

	hattrie_iter_t *i = hattrie_iter_begin(tree, 1);
	while(!hattrie_iter_finished(i)) {
		result = function((zone_node_t **)hattrie_iter_val(i), data);
		if (result != KNOT_EOK) {
			break;
		}
		hattrie_iter_next(i);
	}
	hattrie_iter_free(i);

	return result;
}

int zone_tree_apply(zone_tree_t *tree,
                    zone_tree_apply_cb_t function,
                    void *data)
{
	if (function == NULL) {
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
		return KNOT_EOK;
	}

	return hattrie_apply_rev(tree, (int (*)(value_t*,void*))function, data);
}

void zone_tree_free(zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}
	hattrie_free(*tree);
	*tree = NULL;
}

static int zone_tree_free_node(zone_node_t **node, void *data)
{
	UNUSED(data);
	if (node) {
		node_free(node, NULL);
	}
	return KNOT_EOK;
}

void zone_tree_deep_free(zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}

	zone_tree_apply(*tree, zone_tree_free_node, NULL);
	zone_tree_free(tree);
}
