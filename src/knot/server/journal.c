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

#include "knot/server/journal.h"
#include "libknot/rrtype/soa.h"
#include "libknot/rrset.h"
#include "knot/server/serialization.h"
#include "libknot/internal/macros.h"

/*! \brief Infinite file size limit. */
#define FSLIMIT_MAX (100 * 1024 * 1024 * (size_t) 1024)
/*! \brief Minimum journal size. */
#define FSLIMIT_MIN (1 * 1024 * 1024)
/*! \brief How many deletes per transaction do we perform. */
#define SYNC_BATCH 100
/*! \brief Define for mdb_drop call, not define for a batch removal. */
#define JOURNAL_DROP_FLUSH

static inline void journal_pack_to(uint8_t * data, uint32_t to)
{
	*((uint32_t *) data) = to;
}

static inline uint32_t journal_unpack_to(uint8_t * data)
{
	return *((uint32_t *) data);
}

static inline char * journal_get_ch(char * data)
{
	return data + sizeof(uint32_t);
}

static int load_changeset(journal_t *journal, namedb_val_t *val, knot_dname_t *zone_name, list_t *chgs)
{
	changeset_t *ch = changeset_new(zone_name);
	if (ch == NULL) {
		return KNOT_ENOMEM;
	}

	/* Read journal entry. */
	int ret = changeset_unpack_from(ch, val->data, val->len);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Insert into changeset list. */
	add_tail(chgs, &ch->n);

	return KNOT_EOK;
}

static int store_changeset(changeset_t *ch, journal_t *j)
{
	assert(ch != NULL);
	assert(j != NULL);
	
	int ret;
	
	uint32_t k = knot_soa_serial(&ch->soa_from->rrs);
	
	namedb_val_t key = { &k, sizeof(k) };
	
	size_t entry_size = 0;
	ret = changeset_binary_size(ch, &entry_size);
	assert(ret == KNOT_EOK);
	
	/* Reserve space for the journal entry. */
	namedb_val_t val;
	val.len = entry_size;// + sizeof(uint32_t);
	val.data = malloc(val.len);
	if (val.data == NULL) {
		return KNOT_ENOMEM;
	}
	
	//journal_pack_to(val.data, knot_soa_serial(&ch->soa_to->rrs));
	//ret = serialize_and_store_chgset(ch, journal_get_ch(val.data), entry_size);
	ret = serialize_and_store_chgset(ch, val.data, val.len);
	if (ret != KNOT_EOK) {
		goto end;
	}
	
	namedb_txn_t txn;
	ret = j->db_api->txn_begin(j->db, &txn, 0);
	if (ret != KNOT_EOK) {
		goto end;
	}
	
	ret = j->db_api->insert(&txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		ret = KNOT_EBUSY;
		j->db_api->txn_abort(&txn);
		goto end;
	}
	
	ret = j->db_api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		j->db_api->txn_abort(&txn);
	}
	
	
end:
	free(val.data);
	return ret;
}

journal_t* journal_open(const char *path, size_t fslimit)
{
	if (path == NULL) {
		return NULL;
	}
	
	journal_t *j = malloc(sizeof(*j));
	if (j == NULL) {
		return NULL;
	}
	
	memset(j, 0, sizeof(journal_t));
	
	/* Set file size. */
	if (fslimit == 0) {
		j->fslimit = FSLIMIT_MAX;
	} else if (fslimit < FSLIMIT_MIN) {
		goto fail;
	} else {
		j->fslimit = fslimit;
	}
	
	/* Copy path. */
	j->path = strdup(path);
	if (j->path == NULL) {
		goto fail;
	}
	
	j->db_api = namedb_lmdb_api();
	
	struct namedb_lmdb_opts opts = { .path = path, .mapsize = j->fslimit };
	
	/* Init DB. */
	int ret = j->db_api->init(&j->db, NULL, &opts);
	if (ret != KNOT_EOK) {
		free(j->path);
		goto fail;
	}
	
	return j;
	
fail:
	free(j);
	return NULL;
}

int journal_close(journal_t **j)
{
	/* Check journal. */
	if (j == NULL || *j == NULL) {
		return KNOT_EINVAL;
	}
	
	journal_t *dj = *j;

	/* Deinit DB. */
	dj->db_api->deinit(dj->db);

	/* Free allocated resources. */
	free(dj->path);
	free(dj);
	*j = NULL;

	return KNOT_EOK;
}

bool journal_exists(const char *path)
{
	UNUSED(path);
	
	return true;
}

int journal_load_changesets(journal_t *j, knot_dname_t *zone_name, 
                            list_t *dst, uint32_t from, uint32_t to)
{
	if (!j || !zone_name || !dst) {
		return KNOT_EINVAL;
	}
	
	int ret;
	
	namedb_txn_t txn;
	ret = j->db_api->txn_begin(j->db, &txn, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}
	
	/* Reserve space for the journal key. */
	namedb_val_t key;
	uint32_t key_data;
	key.len = sizeof(key_data);
	key.data = &key_data;
	*((uint32_t *) key.data) = from;
	
	namedb_val_t val;
	
	
	/* Note: keys made of <from><to> are not necessary. We never use 
	 * the <to> part in the key. We use the <to> part to look up next 
	 * changeset using it as another <from> part. We now have the <to> 
	 * part moved from the key side to the value side. 
	 */
	
	ret = j->db_api->find(&txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		goto abort;
	}
	
	while (ret == KNOT_EOK) {
		ret = load_changeset(j, &val, zone_name, dst);
		if (ret != KNOT_EOK) {
			goto abort;
		}
		
		changeset_t *last = TAIL(*dst);
		*((uint32_t *) key.data) = knot_soa_serial(&last->soa_to->rrs);
		
		ret = j->db_api->find(&txn, &key, &val, 0);
	}
	
	/* It's okay, we just found none of that key. */
	if (ret == KNOT_ENOENT) {
		ret = KNOT_EOK;
	}
	
abort:
	if (ret == KNOT_EOK)
		j->db_api->txn_commit(&txn);
	else
		j->db_api->txn_abort (&txn);

	return ret;
}

int journal_store_changesets(journal_t *journal, list_t *src)
{
	if (journal == NULL || src == NULL) {
		return KNOT_EINVAL;
	}
	
	int ret;
	
	/* Begin writing to journal. */
	changeset_t *chs = NULL;
	WALK_LIST(chs, *src) {
		ret = store_changeset(chs, journal);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	return ret;
}

int journal_store_changeset(journal_t *journal, changeset_t *ch)
{
	if (journal == NULL || ch == NULL) {
		return KNOT_EINVAL;
	}

	int ret = store_changeset(ch, journal);

	return ret;
}

int journal_mark_synced(journal_t *j)
{
	if (j == NULL) {
		return KNOT_EINVAL;
	}
	
#ifdef JOURNAL_DROP_FLUSH
	int ret;
#else	
	int ret, count, i;
	namedb_iter_t *iter;
#endif
	
	namedb_txn_t txn;
	ret = j->db_api->txn_begin(j->db, &txn, 0);
	if (ret != KNOT_EOK) {
		return KNOT_ENOMEM;
	}
	
	
#ifdef JOURNAL_DROP_FLUSH
	ret = j->db_api->clear(&txn);
	if (ret != KNOT_EOK) {
		j->db_api->txn_abort(&txn);
		return ret;
	}
#else
	count = j->db_api->count(&txn);
#endif

	ret = j->db_api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		j->db_api->txn_abort(&txn);
		return ret;
	}

#ifdef JOURNAL_DROP_FLUSH
	return KNOT_EOK;
#else
	namedb_val_t key;
	
	while (count > 0) {
		ret = j->db_api->txn_begin(j->db, &txn, 0);
		if (ret != KNOT_EOK) {
			return KNOT_ENOMEM;
		}
		
		iter = j->db_api->iter_begin(&txn, NAMEDB_FIRST);
		if (iter == NULL) {
			j->db_api->txn_abort(&txn);
			return KNOT_ENOMEM;
		}
		
		for (i = 0; i < SYNC_BATCH; ++i) {
			ret = j->db_api->iter_key(iter, &key);
			if (ret != KNOT_EOK) {
				j->db_api->txn_abort(&txn);
				return ret;
			}
			
			ret = j->db_api->del(&txn, &key);
			if (ret != KNOT_EOK) {
				j->db_api->txn_abort(&txn);
				return ret;
			}
			
			iter = j->db_api->iter_next(iter);
			if (iter == NULL) {
				break;
			}
		}
		
		j->db_api->iter_finish(iter);
		
		count = j->db_api->count(&txn);
		
		ret = j->db_api->txn_commit(&txn);
		if (ret != KNOT_EOK) {
			j->db_api->txn_abort(&txn);
			return ret;
		}
	}
	
	return KNOT_EOK;
#endif
}


