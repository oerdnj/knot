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
/*!
 * \file
 *
 * Key and Signature Policy access.
 *
 * \defgroup kasp KASP
 *
 * Key and Signature Policy access.
 *
 * The module provides access to Key and Signature Policy (KASP), which
 * keeps a signing state of a zone, zone signing policies, a reference
 * to key stores.
 *
 * The functionality of the module is incomplete.
 *
 * Example use:
 *
 * ~~~~~ {.c}
 *
 * int result;
 * dnssec_kasp_t *kasp = NULL;
 * dnssec_kasp_zone_t *zone = NULL;
 * dnssec_list_t *keys = NULL;
 *
 * // create API context
 * dnssec_kasp_init_dir(&kasp);
 *
 * // open KASP
 * result = dnssec_kasp_open_dir(kasp, "keydir");
 * if (result != DNSSEC_EOK) {
 *     return result;
 * }
 *
 * // get zone state of 'example.com.'
 * result = dnssec_kasp_zone_load(kasp, "example.com", &zone);
 * if (result != DNSSEC_EOK) {
 *     dnssec_kasp_close(kasp);
 *     return result;
 * }
 *
 * // retrieve zone keys
 * keys = dnssec_kasp_zone_get_keys(zone);
 * if (keys == NULL) {
 *     dnssec_kasp_zone_free(zone);
 *     dnssec_kasp_close(kasp);
 *     return KNOT_ENOMEM;
 * }
 *
 * // list key IDs and it they are active
 * time_t now = time(NULL);
 * dnssec_list_foreach(item, keys) {
 *     dnssec_kasp_key_t *key = dnssec_item_get(item);
 *     bool active = key->timing.active <= now && now < key->timing.retire;
 *     printf("key %s is %s\n", dnssec_key_get_id(key->key),
 *                              active ? "active" : "inactive");
 * }
 *
 * // cleanup
 * dnssec_kasp_zone_free_keys(keys);
 * dnssec_kasp_zone_free(zone);
 * dnssec_kasp_close(kasp);
 * dnssec_kasp_deinit(kasp);
 *
 * ~~~~~
 *
 * @{
 */

#pragma once

#include <dnssec/key.h>
#include <dnssec/list.h>
#include <stdbool.h>
#include <time.h>

struct dnssec_kasp;

/*!
 * KASP store.
 */
typedef struct dnssec_kasp dnssec_kasp_t;

/*!
 * Initialize default KASP state store context.
 *
 * This KASP provider stores the state in JSON files in a directory.
 *
 * \param[out] kasp  Pointer to KASP store instance.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_kasp_init_dir(dnssec_kasp_t **kasp);

/*!
 * Deinitialize KASP store context.
 *
 * \param kasp    KASP store handle.
 */
void dnssec_kasp_deinit(dnssec_kasp_t *kasp);

/*!
 * Initialize KASP store.
 *
 * \param kasp    KASP store handle.
 * \param config  KASP store configuration string.
 */
int dnssec_kasp_init(dnssec_kasp_t *kasp, const char *config);

/*!
 * Open KASP store.
 *
 * \param kasp    KASP store handle.
 * \param config  KASP store configuration string.
 */
int dnssec_kasp_open(dnssec_kasp_t *kasp, const char *config);

/*!
 * Close KASP store.
 *
 * \param kasp  KASP store to be closed.
 */
void dnssec_kasp_close(dnssec_kasp_t *kasp);

struct dnssec_kasp_zone;

/*!
 * Zone state structure in the KASP.
 */
typedef struct dnssec_kasp_zone dnssec_kasp_zone_t;

/*!
 * Create new KASP zone.
 *
 * \param name  Name of the zone to be created.
 *
 * \return Pointer to KASP zone.
 */
dnssec_kasp_zone_t *dnssec_kasp_zone_new(const char *name);

/*!
 * Free a KASP zone instance.
 *
 * \param zone  Zone to be freed.
 */
void dnssec_kasp_zone_free(dnssec_kasp_zone_t *zone);

/*!
 * Retrieve a zone from the KASP
 *
 * \param kasp       KASP instance.
 * \param zone_name  Name of the zone to be retrieved.
 * \param zone       Loaded zone.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_kasp_zone_load(dnssec_kasp_t *kasp, const char *zone_name,
			  dnssec_kasp_zone_t **zone);

/*!
 * Save the zone state into the KASP.
 *
 * \param kasp  KASP instance.
 * \param zone  Zone to be saved.
 */
int dnssec_kasp_zone_save(dnssec_kasp_t *kasp, dnssec_kasp_zone_t *zone);

/*!
 * Remove zone from KASP.
 *
 * \param kasp       KASP instance.
 * \param zone_name  Zone to be removed.
 */
int dnssec_kasp_zone_remove(dnssec_kasp_t *kasp, const char *zone_name);

/*!
 * Get list of zones in the KASP.
 *
 * \param[in]  kasp  KASP instance.
 * \param[out] list  List of zones (as strings).
 */
int dnssec_kasp_zone_list(dnssec_kasp_t *kasp, dnssec_list_t **list);

struct dnssec_kasp_policy;

/*!
 * Key and signature policy.
 */
typedef struct dnssec_kasp_policy dnssec_kasp_policy_t;

struct dnssec_kasp_event;

/*!
 * External signing policy event.
 */
typedef struct dnssec_kasp_event dnssec_kasp_event_t;

/*!
 * KASP key timing information.
 */
typedef struct dnssec_kasp_key_timing {
	time_t publish;		/*!< Time of DNSKEY record publication. */
	time_t active;		/*!< Start of RRSIG records generating. */
	time_t retire;		/*!< End of RRSIG records generating. */
	time_t remove;		/*!< Time of DNSKEY record removal. */
} dnssec_kasp_key_timing_t;

/*!
 * Zone key.
 */
typedef struct dnssec_kasp_key {
	dnssec_key_t *key;			/*!< Instance of the key. */
	dnssec_kasp_key_timing_t timing;	/*!< Key timing information. */
} dnssec_kasp_key_t;

/*!
 * Check if DNSKEY is published in the zone.
 */
bool dnssec_kasp_key_is_published(dnssec_kasp_key_timing_t *timing, time_t at);

/*!
 * Check if RRSIGs are present in the zone.
 */
bool dnssec_kasp_key_is_active(dnssec_kasp_key_timing_t *timing, time_t at);

/*!
 * Check if key is published or active.
 *
 * \param timing  Key timing metadata.
 * \param at      Time to check the metadata against.
 */
bool dnssec_kasp_key_is_used(dnssec_kasp_key_timing_t *timing, time_t at);

/*!
 * Get the set of keys associated with the zone.
 */
dnssec_list_t *dnssec_kasp_zone_get_keys(dnssec_kasp_zone_t *zone);

/*! @} */