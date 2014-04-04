/*!
 * \file rr.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief API for manipulating RRs and RR arrays.
 *
 * \addtogroup libknot
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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "common/mempattern.h"

/* ---------------------------- Single RR ----------------------------------- */

/*!
 * \brief knot_rr_t Array holding single RR payload, i.e. ttl, size and RDATA.
 */
typedef uint8_t knot_rr_t;

/* ------------------------- RR getters/setters ----------------------------- */

/*!
 * \brief Returns RDATA size of single RR.
 * \param rr  RR whose size we want.
 * \return  RR size.
 */
uint16_t knot_rr_rdata_size(const knot_rr_t *rr);

/*!
 * \brief Sets size for given RR.
 * \param rr    RR whose size we want to set.
 * \param size  Size to be set.
 */
void knot_rr_set_size(knot_rr_t *rr, uint16_t size);

/*!
 * \brief Returns TTL of single RR.
 * \param rr  RR whose TTL we want.
 * \return  RR TTL.
 */
uint32_t knot_rr_ttl(const knot_rr_t *rr);

/*!
 * \brief Sets TTL for given RR.
 * \param rr   RR whose TTL we want to set.
 * \param ttl  TTL to be set.
 */
void knot_rr_set_ttl(knot_rr_t *rr, uint32_t ttl);

/*!
 * \brief Returns pointer to RR data.
 * \param rr  RR whose data we want.
 * \return RR data pointer.
 */
uint8_t *knot_rr_rdata(const knot_rr_t *rr);

/* ----------------------------- RR misc ------------------------------------ */

/*!
 * \brief Returns actual size of RR structure for given RDATA size.
 * \param size  RDATA size.
 * \return Actual structure size.
 */
size_t knot_rr_array_size(uint16_t size);

/*!
 * \brief Canonical comparison of two RRs.
 * \param rr1  First RR to compare.
 * \param rr2  Second RR to compare.
 * \retval 0 if rr1 == rr2.
 * \retval < 0 if rr1 < rr2.
 * \retval > 0 if rr1 > rr2.
 */
int knot_rr_cmp(const knot_rr_t *rr1, const knot_rr_t *rr2);

/* --------------------------- Multiple RRs ----------------------------------*/

/*!< \brief Array of RRs. */
typedef struct knot_rrs {
	uint16_t rr_count;  /*!< \brief Count of RRs stored in the structure. */
	knot_rr_t *data;    /*!< \brief Actual data, canonically sorted. */
} knot_rrs_t;

/* -------------------------- RRs init/clear ---------------------------------*/

/*!
 * \brief Initializes RRS structure.
 * \param rrs  Structure to be initialized.
 */
void knot_rrs_init(knot_rrs_t *rrs);

/*!
 * \brief Frees data initialized by RRS structure, but not the structure itself.
 * \param rrs  Structure to be cleared.
 * \param mm   Memory context used to create allocations.
 */
void knot_rrs_clear(knot_rrs_t *rrs, mm_ctx_t *mm);

/*!
 * \brief Deep copies RRS structure. All data are duplicated.
 * \param dst  Copy destination.
 * \param src  Copy source.
 * \param mm   Memory context.
 * \return KNOT_E*
 */
int knot_rrs_copy(knot_rrs_t *dst, const knot_rrs_t *src, mm_ctx_t *mm);

/* ----------------------- RRs getters/setters ------------------------------ */

/*!
 * \brief Gets RR from RRS structure, using given position.
 * \param rrs  RRS structure to get RR from.
 * \param pos  Position to use.
 * \return Pointer to RR at \a pos position.
 */
knot_rr_t *knot_rrs_rr(const knot_rrs_t *rrs, size_t pos);

/*!
 * \brief Gets RDATA from RR at \a pos position.
 * \param rrs  RRS to get RDATA from.
 * \param pos  Position to use.
 * \return Pointer to RDATA of RR at \a pos position.
 */
uint8_t *knot_rrs_rr_rdata(const knot_rrs_t *rrs, size_t pos);

/*!
 * \brief Gets size from RR at \a pos position.
 * \param rrs  RRS to get size from.
 * \param pos  Position to use.
 * \return Size of RR at \a pos position.
 */
uint16_t knot_rrs_rr_size(const knot_rrs_t *rrs, size_t pos);

/*!
 * \brief Gets TTL from RR at \a pos position.
 * \param rrs  RRS to get TTL from.
 * \param pos  Position to use.
 * \return Size of TTL at \a pos position.
 */
uint32_t knot_rrs_rr_ttl(const knot_rrs_t *rrs, size_t pos);

/* ----------------------- RRs RR manipulation ------------------------------ */

/*!
 * \brief Adds single RR into RRS structure. All data are copied.
 * \param rrs  RRS structure to add RR into.
 * \param rr   RR to add.
 * \param mm   Memory context.
 * \return KNOT_E*
 */
int knot_rrs_add_rr(knot_rrs_t *rrs, const knot_rr_t *rr, mm_ctx_t *mm);

/*!
 * \brief Removes RR at a given position from RRS structure. RR is dropped.
 * \param rrs  RRS structure to remove from.
 * \param pos  Position to use.
 * \param mm   Memory context.
 * \return KNOT_E*
 */
int knot_rrs_remove_rr_at_pos(knot_rrs_t *rrs, size_t pos, mm_ctx_t *mm);

/* ----------------------------- RRs misc ----------------------------------- */

/*!
 * \brief RRS equality check.
 * \param rrs1  First RRS to be compared.
 * \param rrs2  Second RRS to be compared.
 * \retval true if rrs1 == rrs2.
 * \retval false if rrs1 != rrs2.
 */
bool knot_rrs_eq(const knot_rrs_t *rrs1, const knot_rrs_t *rrs2);

/*!
 * \brief Creates new RRS using \a rrsig_rrs as a source. Only those RRs that
 *        cover given \a type are copied into \a out_sig
 * \param type       Covered type.
 * \param rrsig_rrs  Source RRS.
 * \param out_sig    Output RRS.
 * \param mm         Memory context.
 * \return KNOT_E*
 */
int knot_rrs_synth_rrsig(uint16_t type, const knot_rrs_t *rrsig_rrs,
                         knot_rrs_t *out_sig, mm_ctx_t *mm);

/*!
 * \brief Merges two RRS into the first one. Second RRS is left intact.
 *        Canonical order is preserved.
 * \param rrs1  Destination RRS (merge here).
 * \param rrs2  RRS to be merged (merge from).
 * \param mm    Memory context.
 * \return KNOT_E*
 */
int knot_rrs_merge(knot_rrs_t *rrs1, const knot_rrs_t *rrs2, mm_ctx_t *mm);
