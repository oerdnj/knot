/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file zone-sign.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Interface for DNSSEC signing of zones.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include "knot/updates/zone-update.h"
#include "knot/updates/zone-read.h"
#include "knot/zone/contents.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-keys.h"

/*!
 * \brief Update zone signatures and store performed changes in changeset.
 *
 * Updates RRSIGs, NSEC(3)s, and DNSKEYs.
 *
 * \param zone        Zone to be signed.
 * \param zone_keys   Zone keys.
 * \param dnssec_ctx  DNSSEC context.
 * \param changeset   Changeset to be updated.
 * \param expire_at   Time, when the oldest signature in the zone expires.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign(zone_update_t *update,
                   const zone_keyset_t *zone_keys,
                   const kdnssec_ctx_t *dnssec_ctx,
                   uint32_t *expire_at);

/*!
 * \brief Check if zone SOA signatures are expired.
 *
 * \param zone       Zone to be signed.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return True if zone SOA signatures need update, false othewise.
 */
bool knot_zone_sign_soa_expired(zone_update_t *update,
                                const zone_keyset_t *zone_keys,
                                const kdnssec_ctx_t *dnssec_ctx);

int knot_zone_sign_update_soa(const knot_rrset_t *soa,
                              const knot_rrset_t *rrsigs,
                              const zone_keyset_t *zone_keys,
                              const kdnssec_ctx_t *dnssec_ctx,
                              zone_update_t *update);

/*!
 * \brief Sign changeset created by DDNS or zone-diff.
 *
 * \param zone New zone contents.
 * \param in_ch Changeset created bvy DDNS or zone-diff
 * \param out_ch New records will be added to this changeset.
 * \param zone_keys Keys to use for signing.
 * \param policy DNSSEC signing policy.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign_changeset(zone_update_t *update,
                             const zone_keyset_t *zone_keys,
                             const kdnssec_ctx_t *dnssec_ctx);

/*!
 * \brief Checks whether RRSet in a node has to be signed. Will not return
 *        true for all types that should be signed, do not use this as an
 *        universal function, it is implementation specific.
 *
 * \param node         Node containing the RRSet.
 * \param rrset        RRSet we are checking for.
 * \param table        Optional hat trie with already signed RRs.
 * \param should_sign  Set to true if RR should be signed, false otherwise.
 *
 * \return KNOT_E*
 */
bool knot_zone_sign_rr_should_be_signed(const zone_node_t *node,
                                        const knot_rrset_t *rrset);

/*! @} */
