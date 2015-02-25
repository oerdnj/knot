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
	namedb_t * db;              /*!< DB handler. */
	const namedb_api_t *db_api; /*!< DB API backend. */
	char *path;                 /*!< Path to journal file. */
	size_t fslimit;             /*!< File size limit. */
} journal_t;

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
                            list_t *dst, uint32_t from);

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

