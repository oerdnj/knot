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
 * \file journal.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 * \author Dominik Taborsky <dominik.taborsky@nic.cz>
 *
 * \brief Journal for storing transactions on permanent storage.
 *
 * We're using namedb now, which was using LMDB as a backend 
 * at the time of writing.
 * \addtogroup utils
 * @{
 */

#pragma once

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "knot/updates/changesets.h"
#include "libknot/internal/namedb/namedb_lmdb.h"
#include "libknot/dname.h"

/*!
 * \brief Journal entry flags.
 */
typedef enum journal_flag_t {
	JOURNAL_NULL  = 0 << 0, /*!< Invalid journal entry. */
	JOURNAL_FREE  = 1 << 0, /*!< Free journal entry. */
	JOURNAL_VALID = 1 << 1, /*!< Valid journal entry. */
	JOURNAL_DIRTY = 1 << 2  /*!< Journal entry cannot be evicted. */
} journal_flag_t;

/*!
 * \brief Journal node structure.
 *
 * Each node represents journal entry and points
 * to position of the data in the permanent storage.
 */
typedef struct journal_node
{
	uint64_t id;    /*!< Node ID. */
	uint16_t flags; /*!< Node flags. */
	uint16_t next;  /*!< UNUSED */
	uint32_t pos;   /*!< Position in journal file. */
	uint32_t len;   /*!< Entry data length. */
} journal_node_t;

/*!
 * \brief Journal structure.
 *
 * Journal organizes entries as nodes.
 * Nodes are stored in-memory for fast lookup and also
 * backed by a permanent storage.
 * Each journal has a fixed number of nodes.
 *
 */
typedef struct journal
{
	namedb_t * db;          /*!< DB handler. */
	const namedb_api_t *db_api;/*!< DB API backend. */
	char *path;             /*!< Path to journal file. */
	uint16_t tmark;         /*!< Transaction start mark. */
	uint16_t max_nodes;     /*!< Number of nodes. */
	uint16_t qhead;         /*!< Node queue head. */
	uint16_t qtail;         /*!< Node queue tail. */
	uint16_t bflags;        /*!< Initial flags for each written node. */
	size_t fsize;           /*!< Journal file size. */
	size_t fslimit;         /*!< File size limit. */
	journal_node_t free;    /*!< Free segment. */
	journal_node_t *nodes;  /*!< Array of nodes. */
} journal_t;

/*
 * Journal defaults and constants.
 */
#define JOURNAL_NCOUNT 1024 /*!< Default node count. */
//#define JOURNAL_MAGIC {'k', 'n', 'o', 't', '1', '5', '2'}
//#define MAGIC_LENGTH 7
/* HEADER = magic, crc, max_entries, qhead, qtail */
//#define JOURNAL_HSIZE (MAGIC_LENGTH + sizeof(uint32_t) + sizeof(uint16_t) * 3)

/*!
 * \brief Open journal.
 *
 * \param path Journal file name.
 * \param fslimit File size limit (0 for no limit).
 *
 * \retval new journal instance if successful.
 * \retval NULL on error.
 */
journal_t* journal_open(const char *path, size_t fslimit);

/*!
 * \brief Close journal file.
 *
 * \param journal Associated journal.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameter.
 */
int journal_close(journal_t **journal);

/*!
 * \brief Check if the journal file is used or not.
 *
 * \param path Journal file.
 *
 * \return true or false
 */
bool journal_exists(const char *path);

/*!
 * \brief Load changesets from journal.
 *
 * \param path Path to journal file.
 * \param dst Store changesets here.
 * \param from Start serial.
 * \param to End serial.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERANGE if given entry was not found.
 * \return < KNOT_EOK on error.
 */
int journal_load_changesets(journal_t *journal, knot_dname_t *zone_name, 
                            list_t *dst, uint32_t from, uint32_t to);

/*!
 * \brief Store changesets in journal.
 *
 * \param src Changesets to store.
 * \param path Path to journal file.
 * \param size_limit Size limit extracted from configuration.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EBUSY when journal is full.
 * \return < KNOT_EOK on other errors.
 */
int journal_store_changesets(journal_t *journal, list_t *src);
int journal_store_changeset(journal_t *journal, changeset_t *change);

/*! \brief Function for unmarking dirty nodes. */
/*!
 * \brief Function for unmarking dirty nodes.
 * \param path Path to journal file.
 * \retval KNOT_ENOMEM if journal could not be opened.
 * \retval KNOT_EOK on success.
 */
int journal_mark_synced(journal_t *journal);

/*! @} */

