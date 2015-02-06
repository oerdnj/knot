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

#include "libknot/errcode.h"

#include "libknot/internal/namedb/namedb_trie.h"
#include "libknot/internal/trie/hat-trie.h"
#include "libknot/internal/mempattern.h"

static value_t *first_val(hattrie_t *t)
{
	hattrie_iter_t *it = hattrie_iter_begin(t, true);
	if (it == NULL) {
		return NULL;
	}

	value_t *val = hattrie_iter_val(it);
	hattrie_iter_free(it);

	return val;
}

static int init(const char *config, namedb_t **db, mm_ctx_t *mm)
{
	if (config != NULL || db == NULL) {
		return KNOT_EINVAL;
	}

	hattrie_t *trie = hattrie_create_n(TRIE_BUCKET_SIZE, mm);
	if (!trie) {
		return KNOT_ENOMEM;
	}

	*db = trie;

	return KNOT_EOK;
}

static void deinit(namedb_t *db)
{
	hattrie_free((hattrie_t *)db);
}

static int txn_begin(namedb_t *db, namedb_txn_t *txn, unsigned flags)
{
	txn->txn = (void *)(size_t)flags;
	txn->db  = db;
	return KNOT_EOK; /* N/A */
}

static int txn_commit(namedb_txn_t *txn)
{
	/* Rebuild order index only for WR transactions. */
	if ((size_t)txn->txn & NAMEDB_RDONLY) {
		return KNOT_EOK;
	}

	hattrie_build_index((hattrie_t *)txn->db);
	return KNOT_EOK;
}

static void txn_abort(namedb_txn_t *txn)
{
}

static int count(namedb_txn_t *txn)
{
	return hattrie_weight((hattrie_t *)txn->db);
}

static int clear(namedb_txn_t *txn)
{
	hattrie_clear((hattrie_t *)txn->db);

	return KNOT_EOK;
}

static int find(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	// Clear non-operation flags.
	const unsigned op = flags & ~(NAMEDB_RDONLY | NAMEDB_SORTED);
	value_t *ret = NULL;
	switch(op) {
	case 0:
		ret = hattrie_tryget((hattrie_t *)txn->db, key->data, key->len);
		break;
	case NAMEDB_LEQ:
		hattrie_find_leq((hattrie_t *)txn->db, key->data, key->len, &ret);
		break;
	case NAMEDB_NEXT:
		hattrie_find_next((hattrie_t *)txn->db, key->data, key->len, &ret);
		break;
	case NAMEDB_FIRST:
		ret = first_val((hattrie_t *)txn->db);
	case NAMEDB_LAST:
		ret = hattrie_find_rightmost_node((hattrie_t *)txn->db);
	default:
		return KNOT_EINVAL;
	}

	if (ret == NULL) {
		return KNOT_ENOENT;
	}

	val->data = *ret;
	val->len  = sizeof(value_t); /* Trie doesn't support storing length. */
	return KNOT_EOK;
}

static int insert(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	value_t *ret = hattrie_get((hattrie_t *)txn->db, key->data, key->len);
	if (ret == NULL) {
		return KNOT_ENOMEM;
	}

	*ret = val->data;
	return KNOT_EOK;
}

static int del(namedb_txn_t *txn, namedb_val_t *key)
{
	return hattrie_del((hattrie_t *)txn->db, key->data, key->len);
}

static namedb_iter_t *iter_begin(namedb_txn_t *txn, unsigned flags)
{
	bool is_sorted = (flags & NAMEDB_SORTED);
	flags &= ~NAMEDB_SORTED;

	/* No operations other than begin are supported right now. */
	if (flags != 0) {
		return NULL;
	}

	return hattrie_iter_begin((hattrie_t *)txn->db, is_sorted);
}

static void iter_set_last(hattrie_iter_t *iter)
{
	
}

static namedb_iter_t *iter_seek(namedb_iter_t *iter, namedb_val_t *key, unsigned flags)
{
	assert(key == NULL);
	switch(flags) {
	case NAMEDB_NOOP:
		return iter;
	case NAMEDB_FIRST:
		hattrie_iter_free(iter);
		iter = malloc(sizeof(*iter));
		if (iter) {
			hattrie_iter_init(iter, NULL, NULL);
		}
		break;
	case NAMEDB_LAST:
		iter_set_last(iter);
		break;
	case NAMEDB_NEXT:
		hattrie_iter_next(iter);
		break;
	case NAMEDB_PREV:
	case NAMEDB_LEQ:
	case NAMEDB_GEQ: assert(0);
	default: break;
	}

	return iter;
}

static namedb_iter_t *iter_next(namedb_iter_t *iter)
{
	if (iter) {
		hattrie_iter_next((hattrie_iter_t *)iter);
		if (hattrie_iter_finished((hattrie_iter_t *)iter)) {
			hattrie_iter_free((hattrie_iter_t *)iter);
			return NULL;
		}
	}

	return iter;
}

static int iter_key(namedb_iter_t *iter, namedb_val_t *val)
{
	val->data = (void *)hattrie_iter_key((hattrie_iter_t *)iter, &val->len);
	if (val->data == NULL) {
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

static int iter_val(namedb_iter_t *iter, namedb_val_t *val)
{
	value_t *ret = hattrie_iter_val((hattrie_iter_t *)iter);
	if (ret == NULL) {
		return KNOT_ENOENT;
	}

	val->data = *ret;
	val->len  = sizeof(value_t);
	return KNOT_EOK;
}

static void iter_finish(namedb_iter_t *iter)
{
	hattrie_iter_free((hattrie_iter_t *)iter);
}

const namedb_api_t *namedb_trie_api(void)
{
	static const namedb_api_t api = {
		"hattrie",
		init, deinit,
		txn_begin, txn_commit, txn_abort,
		count, clear, find, insert, del,
		iter_begin, iter_seek, iter_next, iter_key, iter_val, iter_finish
	};

	return &api;
}
