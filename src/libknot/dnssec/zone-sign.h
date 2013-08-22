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

#ifndef _KNOT_DNSSEC_ZONE_SIGN_H_
#define _KNOT_DNSSEC_ZONE_SIGN_H_

#include "common/hattrie/ahtable.h"
#include "libknot/updates/changesets.h"
#include "libknot/zone/zone-contents.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/dnssec/policy.h"

/*!
 * \brief Update zone signatures and store performed changes in changeset.
 *
 * Updates RRSIGs, NSEC(3)s, and DNSKEYs.
 *
 * \param zone        Zone to be signed.
 * \param zone_keys   Zone keys.
 * \param policy      DNSSEC policy.
 * \param changeset   Changeset to be updated.
 * \param expires_at  Pointer to expiration time of the oldest signature in zone
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign(const knot_zone_contents_t *zone,
                   const knot_zone_keys_t *zone_keys,
                   const knot_dnssec_policy_t *policy,
                   knot_changeset_t *out_ch, uint32_t *expires_at);

/*!
 * \brief Update and sign SOA and store performed changes in changeset.
 *
 * \param zone       Zone including SOA to be updated.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign_update_soa(const knot_rrset_t *soa,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              knot_changeset_t *changeset);

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
bool knot_zone_sign_soa_expired(const knot_zone_contents_t *zone,
                                const knot_zone_keys_t *zone_keys,
                                const knot_dnssec_policy_t *policy);

/*!
 * \brief Sign changeset created by DDNS or zone-diff.
 *
 * \param zone Contents of the updated zone (AFTER zone is switched).
 * \param in_ch Changeset created bvy DDNS or zone-diff
 * \param out_ch New records will be added to this changeset.
 * \param zone_keys Keys to use for signing.
 * \param policy DNSSEC signing policy.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign_changeset(const knot_zone_contents_t *zone,
                             const knot_changeset_t *in_ch,
                             knot_changeset_t *out_ch,
                             const knot_zone_keys_t *zone_keys,
                             const knot_dnssec_policy_t *policy);

/*!
 * \brief Sign NSEC/NSEC3 nodes in changeset and update the changeset.
 *
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign_nsecs_in_changeset(const knot_zone_keys_t *zone_keys,
                                      const knot_dnssec_policy_t *policy,
                                      knot_changeset_t *changeset);

#endif // _KNOT_DNSSEC_ZONE_SIGN_H_

/*! @} */