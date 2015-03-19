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
#include <stdlib.h>
#include <inttypes.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/updates/ddns.h"
#include "knot/updates/changesets.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/serial.h"
#include "libknot/packet/pkt.h"
#include "libknot/consts.h"
#include "libknot/rrtype/soa.h"
#include "libknot/internal/mempattern.h"
#include "libknot/descriptor.h"
#include "libknot/internal/lists.h"

/* ----------------------------- prereq check ------------------------------- */

/*!< \brief Clears prereq RRSet list. */
static void rrset_list_clear(list_t *l)
{
	node_t *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, *l) {
		ptrnode_t *ptr_n = (ptrnode_t *)n;
		knot_rrset_t *rrset = (knot_rrset_t *)ptr_n->d;
		knot_rrset_free(&rrset, NULL);
		free(n);
	};
}

/*!< \brief Adds RR to prereq RRSet list, merges RRs into RRSets. */
static int add_rr_to_list(list_t *l, const knot_rrset_t *rr)
{
	node_t *n;
	WALK_LIST(n, *l) {
		ptrnode_t *ptr_n = (ptrnode_t *)n;
		knot_rrset_t *rrset = (knot_rrset_t *)ptr_n->d;
		if (knot_rrset_equal(rr, rrset, KNOT_RRSET_COMPARE_HEADER)) {
			return knot_rdataset_merge(&rrset->rrs, &rr->rrs, NULL);
		}
	};

	knot_rrset_t *rr_copy = knot_rrset_copy(rr, NULL);
	if (rr_copy == NULL) {
		return KNOT_ENOMEM;
	}
	return ptrlist_add(l, rr_copy, NULL) != NULL ? KNOT_EOK : KNOT_ENOMEM;
}

/*!< \brief Checks whether RRSet exists in the zone. */
static int check_rrset_exists(zone_update_t *update, const knot_rrset_t *rrset,
                              uint16_t *rcode)
{
	assert(rrset->type != KNOT_RRTYPE_ANY);

	const zone_node_t *node = zone_update_get_node(update, rrset->owner);
	if (node == NULL || !node_rrtype_exists(node, rrset->type)) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	} else {
		knot_rrset_t found = node_rrset(node, rrset->type);
		assert(!knot_rrset_empty(&found));
		if (knot_rrset_equal(&found, rrset, KNOT_RRSET_COMPARE_WHOLE)) {
			return KNOT_EOK;
		} else {
			*rcode = KNOT_RCODE_NXRRSET;
			return KNOT_EPREREQ;
		}
	}
}

/*!< \brief Checks whether RRSets in the list exist in the zone. */
static int check_stored_rrsets(list_t *l, zone_update_t *update,
                               uint16_t *rcode)
{
	node_t *n;
	WALK_LIST(n, *l) {
		ptrnode_t *ptr_n = (ptrnode_t *)n;
		knot_rrset_t *rrset = (knot_rrset_t *)ptr_n->d;
		int ret = check_rrset_exists(update, rrset, rcode);
		if (ret != KNOT_EOK) {
			return ret;
		}
	};

	return KNOT_EOK;
}

/*!< \brief Checks whether node of given owner, with given type exists. */
static bool check_type(zone_update_t *update, const knot_rrset_t *rrset)
{
	assert(rrset->type != KNOT_RRTYPE_ANY);
	const zone_node_t *node = zone_update_get_node(update, rrset->owner);
	if (node == NULL || !node_rrtype_exists(node, rrset->type)) {
		return false;
	}

	return true;
}

/*!< \brief Checks whether RR type exists in the zone. */
static int check_type_exist(zone_update_t *update,
                            const knot_rrset_t *rrset, uint16_t *rcode)
{
	assert(rrset->rclass == KNOT_CLASS_ANY);
	if (check_type(update, rrset)) {
		return KNOT_EOK;
	} else {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	}
}

/*!< \brief Checks whether RR type is not in the zone. */
static int check_type_not_exist(zone_update_t *update,
                                const knot_rrset_t *rrset, uint16_t *rcode)
{
	assert(rrset->rclass == KNOT_CLASS_NONE);
	if (check_type(update, rrset)) {
		*rcode = KNOT_RCODE_YXRRSET;
		return KNOT_EPREREQ;
	} else {
		return KNOT_EOK;
	}
}

/*!< \brief Checks whether DNAME is in the zone. */
static int check_in_use(zone_update_t *update,
                        const knot_dname_t *dname, uint16_t *rcode)
{
	const zone_node_t *node = zone_update_get_node(update, dname);
	if (node == NULL || node->rrset_count == 0) {
		*rcode = KNOT_RCODE_NXDOMAIN;
		return KNOT_EPREREQ;
	} else {
		return KNOT_EOK;
	}
}

/*!< \brief Checks whether DNAME is not in the zone. */
static int check_not_in_use(zone_update_t *update,
                            const knot_dname_t *dname, uint16_t *rcode)
{
	const zone_node_t *node = zone_update_get_node(update, dname);
	if (node == NULL || node->rrset_count == 0) {
		return KNOT_EOK;
	} else {
		*rcode = KNOT_RCODE_YXDOMAIN;
		return KNOT_EPREREQ;
	}
}

/*!< \brief Returns true if rrset has 0 data or RDATA of size 0 (we need TTL).*/
static bool rrset_empty(const knot_rrset_t *rrset)
{
	uint16_t rr_count = rrset->rrs.rr_count;
	if (rr_count == 0) {
		return true;
	}
	if (rr_count == 1) {
		const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, 0);
		return knot_rdata_rdlen(rr) == 0;
	}
	return false;
}

/*!< \brief Checks prereq for given packet RR. */
static int process_prereq(const knot_rrset_t *rrset, uint16_t qclass,
                          zone_update_t *update, uint16_t *rcode,
                          list_t *rrset_list)
{
	if (knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, 0)) != 0) {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	if (!knot_dname_in(update->zone->apex->owner, rrset->owner)) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	if (rrset->rclass == KNOT_CLASS_ANY) {
		if (!rrset_empty(rrset)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
		if (rrset->type == KNOT_RRTYPE_ANY) {
			return check_in_use(update, rrset->owner, rcode);
		} else {
			return check_type_exist(update, rrset, rcode);
		}
	} else if (rrset->rclass == KNOT_CLASS_NONE) {
		if (!rrset_empty(rrset)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
		if (rrset->type == KNOT_RRTYPE_ANY) {
			return check_not_in_use(update, rrset->owner, rcode);
		} else {
			return check_type_not_exist(update, rrset, rcode);
		}
	} else if (rrset->rclass == qclass) {
		// Store RRs for full check into list
		int ret = add_rr_to_list(rrset_list, rrset);
		if (ret != KNOT_EOK) {
			*rcode = KNOT_RCODE_SERVFAIL;
		}
		return ret;
	} else {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}
}

/* --------------------------- DDNS processing ------------------------------ */

/*!< \brief Checks whether RR was already removed. */
static bool removed_rr(zone_contents_t *z, const knot_rrset_t *rr)
{
	const zone_node_t *n = zone_contents_find_node_for_rr(z, rr);
	if (n == NULL) {
		return false;
	}

	const knot_rdataset_t *rrs = node_rdataset(n, rr->type);
	if (rrs == NULL) {
		return false;
	}

	return knot_rdataset_eq(rrs, &rr->rrs);
}

/*!< \brief Checks whether any CNAME RR under dname was added. */
static bool cname_added(const changeset_t *changeset, const knot_dname_t *d)
{
	const zone_node_t *n = zone_contents_find_node(changeset->add, d);
	return n && node_rrtype_exists(n, KNOT_RRTYPE_CNAME);
}

/*!< \brief Checks whether any RR under given name was added. */
static bool name_added(const changeset_t *changeset, const knot_dname_t *d)
{
	return zone_contents_find_node(changeset->add, d);
}

/*!< \brief Removes RR from changeset, full equality check. */
static void remove_rr_from_changeset(zone_contents_t *z, const knot_rrset_t *rr)
{
	zone_node_t *n = zone_contents_find_node_for_rr(z, rr);
	if (n == NULL) {
		return;
	}

	knot_rdataset_t *rrs = node_rdataset(n, rr->type);
	if (rrs == NULL) {
		return;
	}

	knot_rdataset_subtract(rrs, &rr->rrs, NULL);
	if (rrs->rr_count == 0) {
		node_remove_rdataset(n, rr->type);
	}
}

/*!< \brief Removes RR from list, owner and type check. */
static void remove_header_from_changeset(zone_contents_t *z, const knot_rrset_t *rr)
{
	zone_node_t *n = zone_contents_find_node_for_rr(z, rr);
	if (n == NULL) {
		return;
	}

	knot_rdataset_t *rrs = node_rdataset(n, rr->type);
	if (rrs) {
		knot_rdataset_clear(rrs, NULL);
		node_remove_rdataset(n, rr->type);
	}
}

/*!< \brief Removes RR from list, owner check. */
static void remove_owner_from_changeset(zone_contents_t *z, const knot_dname_t *owner)
{
	zone_node_t *n = (zone_node_t *)zone_contents_find_node(z, owner);
	node_free_rrsets(n, NULL);
}

/* --------------------- true/false helper functions ------------------------ */

static inline bool is_addition(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_IN;
}

static inline bool is_removal(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_NONE || rr->rclass == KNOT_CLASS_ANY;
}

static inline bool is_rr_removal(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_NONE;
}

static inline bool is_rrset_removal(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_ANY && rr->type != KNOT_RRTYPE_ANY;
}

static inline bool is_node_removal(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_ANY && rr->type == KNOT_RRTYPE_ANY;
}

/*!< \brief Returns true if last addition of certain types is to be replaced. */
static bool should_replace(const knot_rrset_t *rrset)
{
	return rrset->type == KNOT_RRTYPE_CNAME ||
	       rrset->type == KNOT_RRTYPE_NSEC3PARAM;
}

/*!< \brief Returns true if node will be empty after update application. */
static bool node_will_be_empty(const zone_node_t *node, knot_dname_t *owner,
                               const changeset_t *changeset)
{
	if (node == NULL && name_added(changeset, owner)) {
		// Node created in update.
		return false;
	}

	if (node == NULL) {
		// Node empty.
		return true;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t node_rrset = node_rrset_at(node, i);
		knot_rrset_t node_rr;
		knot_rrset_init(&node_rr, node->owner, node_rrset.type, KNOT_CLASS_IN);
		for (uint16_t j = 0; j < node_rrset.rrs.rr_count; ++j) {
			knot_rdata_t *add_rr = knot_rdataset_at(&node_rrset.rrs, j);
			int ret = knot_rdataset_add(&node_rr.rrs, add_rr, NULL);
			if (ret != KNOT_EOK) {
				return false;
			}
			if (!removed_rr(changeset->remove, &node_rr)) {
				// One of the RRs from node was not removed.
				knot_rdataset_clear(&node_rr.rrs, NULL);
				return false;
			}
			knot_rdataset_clear(&node_rr.rrs, NULL);
		}
	}

	return true;
}

/*!< \brief Returns true if node contains given RR in its RRSets. */
static bool node_contains_rr(const zone_node_t *node,
                             const knot_rrset_t *rr)
{
	const knot_rdataset_t *zone_rrs = node_rdataset(node, rr->type);
	if (zone_rrs) {
		assert(rr->rrs.rr_count == 1);
		const bool compare_ttls = false;
		return knot_rdataset_member(zone_rrs,
		                            knot_rdataset_at(&rr->rrs, 0),
		                            compare_ttls);
	} else {
		return false;
	}
}

/*!< \brief Returns true if CNAME is in this node. */
static bool adding_to_cname(const knot_dname_t *owner,
                            const zone_node_t *node,
                            changeset_t *changeset)
{
	if (cname_added(changeset, owner)) {
		// Added a CNAME in this update.
		return true;
	}

	if (node == NULL) {
		// Node did not exist before update.
		return false;
	}

	knot_rrset_t cname = node_rrset(node, KNOT_RRTYPE_CNAME);
	if (knot_rrset_empty(&cname)) {
		// Node did not contain CNAME before update.
		return false;
	}

	if (removed_rr(changeset->remove, &cname)) {
		// Node did contain CNAME, but it was removed in this update.
		return false;
	}

	// CNAME present
	return true;
}

/*!< \brief Used to ignore SOA deletions and SOAs with lower serial than zone. */
static bool skip_soa(const knot_rrset_t *rr, int64_t sn)
{
	if (rr->type == KNOT_RRTYPE_SOA &&
	    (rr->rclass == KNOT_CLASS_NONE || rr->rclass == KNOT_CLASS_ANY ||
	     serial_compare(knot_soa_serial(&rr->rrs), sn) <= 0)) {
		return true;
	}

	return false;
}

/* ---------------------- changeset manipulation ---------------------------- */

/*!< \brief Replaces possible singleton RR type in changeset. */
static bool singleton_replaced(changeset_t *changeset,
                               const knot_rrset_t *rr)
{
	if (!should_replace(rr)) {
		return false;
	}

	zone_node_t *n = zone_contents_find_node_for_rr(changeset->add, rr);
	if (n == NULL) {
		return false;
	}

	knot_rdataset_t *rrs = node_rdataset(n, rr->type);
	if (rrs == NULL) {
		return false;
	}

	// Replace singleton RR.
	knot_rdataset_clear(rrs, NULL);
	node_remove_rdataset(n, rr->type);
	node_add_rrset(n, rr, NULL);

	return true;
}

/*!< \brief Adds RR into add section of changeset if it is deemed worthy. */
static int add_rr_to_chgset(const knot_rrset_t *rr, changeset_t *changeset,
                            int *apex_ns_rem)
{
	if (singleton_replaced(changeset, rr)) {
		return KNOT_EOK;
	}

	if (apex_ns_rem) {
		// Increase post update apex NS count.
		(*apex_ns_rem)--;
	}

	return changeset_add_rrset(changeset, rr);
}

/*!< \brief Adds RR into remove section of changeset if it is deemed worthy. */
static int rem_rr_to_chgset(const knot_rrset_t *rr, changeset_t *changeset,
                            int *apex_ns_rem)
{
	if (apex_ns_rem) {
		// Decrease post update apex NS count.
		(*apex_ns_rem)++;
	}

	return changeset_rem_rrset(changeset, rr);
}

/*!< \brief Adds all RRs from RRSet into remove section of changeset. */
static int rem_rrset_to_chgset(const knot_rrset_t *rrset,
                               changeset_t *changeset,
                               int *apex_ns_rem)
{
	knot_rrset_t rr;
	knot_rrset_init(&rr, rrset->owner, rrset->type, rrset->rclass);
	for (uint16_t i = 0; i < rrset->rrs.rr_count; ++i) {
		knot_rdata_t *rr_add = knot_rdataset_at(&rrset->rrs, i);
		int ret = knot_rdataset_add(&rr.rrs, rr_add, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
		ret = rem_rr_to_chgset(&rr, changeset, apex_ns_rem);
		knot_rdataset_clear(&rr.rrs, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/* ------------------------ RR processing logic ----------------------------- */

/* --------------------------- RR additions --------------------------------- */

/*!< \brief Processes CNAME addition (replace or ignore) */
static int process_add_cname(const zone_node_t *node,
                             const knot_rrset_t *rr,
                             changeset_t *changeset)
{
	knot_rrset_t cname = node_rrset(node, KNOT_RRTYPE_CNAME);
	if (!knot_rrset_empty(&cname)) {
		// If they are identical, ignore.
		if (knot_rrset_equal(&cname, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			return KNOT_EOK;
		}

		int ret = rem_rr_to_chgset(&cname, changeset, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}

		return add_rr_to_chgset(rr, changeset, NULL);
	} else if (!node_will_be_empty(node, rr->owner, changeset)) {
		// Other occupied node => ignore.
		return KNOT_EOK;
	} else {
		// Can add.
		return add_rr_to_chgset(rr, changeset, NULL);
	}
}

/*!< \brief Processes NSEC3PARAM addition (ignore when not removed, or non-apex) */
static int process_add_nsec3param(const zone_node_t *node,
                                  const knot_rrset_t *rr,
                                  changeset_t *changeset)
{
	if (node == NULL || !node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		// Ignore non-apex additions
		char *owner = knot_dname_to_str_alloc(rr->owner);
		log_warning("DDNS, refusing to add NSEC3PARAM to non-apex "
		            "node '%s'", owner);
		free(owner);
		return KNOT_EDENIED;
	}
	knot_rrset_t param = node_rrset(node, KNOT_RRTYPE_NSEC3PARAM);
	if (knot_rrset_empty(&param) || removed_rr(changeset->remove, &param)) {
		return add_rr_to_chgset(rr, changeset, NULL);
	}

	char *owner = knot_dname_to_str_alloc(rr->owner);
	log_warning("DDNS, refusing to add second NSEC3PARAM to node '%s'", owner);
	free(owner);

	return KNOT_EOK;
}

/*!
 * \brief Processes SOA addition (ignore when non-apex), lower serials
 *        dropped before.
 */
static int process_add_soa(const zone_node_t *node,
                           const knot_rrset_t *rr,
                           changeset_t *changeset)
{
	if (node == NULL || !node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		// Adding SOA to non-apex node, ignore.
		return KNOT_EOK;
	}

	// Get current SOA RR.
	knot_rrset_t removed = node_rrset(node, KNOT_RRTYPE_SOA);
	if (knot_rrset_equal(&removed, rr, KNOT_RRSET_COMPARE_WHOLE)) {
		// If they are identical, ignore.
		return KNOT_EOK;
	}

	// Store SOA copy into changeset.
	if (changeset->soa_to) {
		// Discard previous SOA - "There can be only one!"
		knot_rrset_free(&changeset->soa_to, NULL);
	}
	knot_rrset_t *soa_cpy = knot_rrset_copy(rr, NULL);
	if (soa_cpy == NULL) {
		return KNOT_ENOMEM;
	}

	changeset->soa_to = soa_cpy;

	return KNOT_EOK;
}

/*!< \brief Adds normal RR, ignores when CNAME exists in node. */
static int process_add_normal(const zone_node_t *node,
                              const knot_rrset_t *rr,
                              changeset_t *changeset,
                              int *apex_ns_rem)
{
	if (adding_to_cname(rr->owner, node, changeset)) {
		// Adding RR to CNAME node, ignore.
		return KNOT_EOK;
	}

	if (node && node_contains_rr(node, rr)) {
		// Adding existing RR, remove removal from changeset if it's there.
		remove_rr_from_changeset(changeset->remove, rr);
		// And ignore.
		return KNOT_EOK;
	}

	const bool apex_ns = node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	                     rr->type == KNOT_RRTYPE_NS;
	return add_rr_to_chgset(rr, changeset, apex_ns ? apex_ns_rem : NULL);
}

/*!< \brief Decides what to do with RR addition. */
static int process_add(const knot_rrset_t *rr,
                       const zone_node_t *node,
                       changeset_t *changeset,
                       int *apex_ns_rem)
{
	switch(rr->type) {
	case KNOT_RRTYPE_CNAME:
		return process_add_cname(node, rr, changeset);
	case KNOT_RRTYPE_SOA:
		return process_add_soa(node, rr, changeset);
	case KNOT_RRTYPE_NSEC3PARAM:
		return process_add_nsec3param(node, rr, changeset);
	default:
		return process_add_normal(node, rr, changeset, apex_ns_rem);
	}
}

/* --------------------------- RR deletions --------------------------------- */

/*!< \brief Removes single RR from zone. */
static int process_rem_rr(const knot_rrset_t *rr,
                          const zone_node_t *node,
                          changeset_t *changeset,
                          int *apex_ns_rem)
{
	const bool apex_ns = node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	                     rr->type == KNOT_RRTYPE_NS;
	if (apex_ns) {
		const knot_rdataset_t *ns_rrs =
			node_rdataset(node, KNOT_RRTYPE_NS);
		if (ns_rrs == NULL) {
			// Zone without apex NS.
			return KNOT_EOK;
		}
		if (*apex_ns_rem == ns_rrs->rr_count - 1) {
			// Cannot remove last apex NS RR.
			return KNOT_EOK;
		}
	}

	// Remove possible previously added RR
	remove_rr_from_changeset(changeset->add, rr);
	if (node == NULL) {
		// Removing from node that did not exists before update
		return KNOT_EOK;
	}

	knot_rrset_t to_modify = node_rrset(node, rr->type);
	if (knot_rrset_empty(&to_modify)) {
		// No such RRSet
		return KNOT_EOK;
	}

	knot_rrset_t intersection;
	knot_rrset_init(&intersection, to_modify.owner, to_modify.type,
	                KNOT_CLASS_IN);
	int ret = knot_rdataset_intersect(&to_modify.rrs, &rr->rrs,
	                                  &intersection.rrs, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (knot_rrset_empty(&intersection)) {
		// No such RR
		return KNOT_EOK;
	}
	assert(intersection.rrs.rr_count == 1);
	ret = rem_rr_to_chgset(&intersection, changeset,
	                       apex_ns ? apex_ns_rem : NULL);
	knot_rdataset_clear(&intersection.rrs, NULL);
	return ret;
}

/*!< \brief Removes RRSet from zone. */
static int process_rem_rrset(const knot_rrset_t *rrset,
                             const zone_node_t *node,
                             changeset_t *changeset)
{
	if (rrset->type == KNOT_RRTYPE_SOA || knot_rrtype_is_dnssec(rrset->type)) {
		// Ignore SOA and DNSSEC removals.
		return KNOT_EOK;
	}

	if (node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	    rrset->type == KNOT_RRTYPE_NS) {
		// Ignore NS apex RRSet removals.
		return KNOT_EOK;
	}

	// Remove all previously added RRs with this owner and type from chgset
	remove_header_from_changeset(changeset->add, rrset);

	if (node == NULL) {
		// no such node in zone, ignore
		return KNOT_EOK;
	}

	if (!node_rrtype_exists(node, rrset->type)) {
		// no such RR, ignore
		return KNOT_EOK;
	}

	knot_rrset_t to_remove = node_rrset(node, rrset->type);
	return rem_rrset_to_chgset(&to_remove, changeset, NULL);
}

/*!< \brief Removes node from zone. */
static int process_rem_node(const knot_rrset_t *rr,
                            const zone_node_t *node, changeset_t *changeset)
{
	// Remove all previously added records with given owner from changeset
	remove_owner_from_changeset(changeset->add, rr->owner);

	if (node == NULL) {
		return KNOT_EOK;
	}

	// Remove all RRSets from node
	for (int i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		int ret = process_rem_rrset(&rrset, node, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*!< \brief Decides what to with removal. */
static int process_remove(const knot_rrset_t *rr,
                          const zone_node_t *node,
                          changeset_t *changeset,
                          int *apex_ns_rem)
{
	if (is_rr_removal(rr)) {
		return process_rem_rr(rr, node, changeset, apex_ns_rem);
	} else if (is_rrset_removal(rr)) {
		return process_rem_rrset(rr, node, changeset);
	} else if (is_node_removal(rr)) {
		return process_rem_node(rr, node, changeset);
	} else {
		return KNOT_EINVAL;
	}
}

/* --------------------------- validity checks ------------------------------ */

/*!< \brief Checks whether addition has not violated DNAME rules. */
static bool sem_check(const knot_rrset_t *rr,
                      const zone_node_t *zone_node,
                      const zone_contents_t *zone)
{
	// Check that we have not added DNAME child
	const knot_dname_t *parent_dname = knot_wire_next_label(rr->owner, NULL);
	const zone_node_t *parent = zone_contents_find_node(zone, parent_dname);

	if (parent == NULL) {
		return true;
	}

	if (node_rrtype_exists(parent, KNOT_RRTYPE_DNAME)) {
		// Parent has DNAME RRSet, refuse update
		return false;
	}

	if (rr->type != KNOT_RRTYPE_DNAME || zone_node == NULL) {
		return true;
	}

	// Check that we have not created node with DNAME children.
	if (zone_node->children > 0) {
		// Updated node has children and DNAME was added, refuse update
		return false;
	}

	return true;
}

/*!< \brief Checks whether we can accept this RR. */
static int check_update(const knot_rrset_t *rrset, const knot_pkt_t *query,
                        uint16_t *rcode)
{
	/* Accept both subdomain and dname match. */
	const knot_dname_t *owner = rrset->owner;
	const knot_dname_t *qname = knot_pkt_qname(query);
	const bool is_sub = knot_dname_is_sub(owner, qname);
	if (!is_sub && !knot_dname_is_equal(owner, qname)) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	if (knot_rrtype_is_dnssec(rrset->type)) {
		*rcode = KNOT_RCODE_REFUSED;
		log_warning("DDNS, refusing to update DNSSEC-related record");
		return KNOT_EDENIED;
	}

	if (rrset->rclass == knot_pkt_qclass(query)) {
		if (knot_rrtype_is_metatype(rrset->type)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else if (rrset->rclass == KNOT_CLASS_ANY) {
		if (!rrset_empty(rrset) ||
		    (knot_rrtype_is_metatype(rrset->type) &&
		     rrset->type != KNOT_RRTYPE_ANY)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else if (rrset->rclass == KNOT_CLASS_NONE) {
		if ((knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, 0)) != 0) ||
		    knot_rrtype_is_metatype(rrset->type)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

/*!< \brief Checks RR and decides what to do with it. */
static int process_rr(const knot_rrset_t *rr, const zone_contents_t *zone,
                      changeset_t *changeset, int *apex_ns_rem)
{
	const zone_node_t *node = zone_contents_find_node(zone, rr->owner);

	if (is_addition(rr)) {
		int ret = process_add(rr, node, changeset, apex_ns_rem);
		if (ret == KNOT_EOK) {
			if (!sem_check(rr, node, zone)) {
				return KNOT_EDENIED;
			}
		}
		return ret;
	} else if (is_removal(rr)) {
		return process_remove(rr, node, changeset, apex_ns_rem);
	} else {
		return KNOT_EMALF;
	}
}

/*!< \brief Maps Knot return code to RCODE. */
static uint16_t ret_to_rcode(int ret)
{
	if (ret == KNOT_EMALF) {
		return KNOT_RCODE_FORMERR;
	} else if (ret == KNOT_EDENIED || ret == KNOT_ETTL) {
		return KNOT_RCODE_REFUSED;
	} else {
		return KNOT_RCODE_SERVFAIL;
	}
}

/* ---------------------------------- API ----------------------------------- */

int ddns_process_prereqs(const knot_pkt_t *query, zone_update_t *update,
                         uint16_t *rcode)
{
	if (query == NULL || rcode == NULL || update == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	list_t rrset_list; // List used to store merged RRSets
	init_list(&rrset_list);

	const knot_pktsection_t *answer = knot_pkt_section(query, KNOT_ANSWER);
	const knot_rrset_t *answer_rr = knot_pkt_rr(answer, 0);
	for (int i = 0; i < answer->count; ++i) {
		// Check what can be checked, store full RRs into list
		ret = process_prereq(&answer_rr[i], knot_pkt_qclass(query),
		                     update, rcode, &rrset_list);
		if (ret != KNOT_EOK) {
			rrset_list_clear(&rrset_list);
			return ret;
		}
	}

	// Check stored RRSets
	ret = check_stored_rrsets(&rrset_list, update, rcode);
	rrset_list_clear(&rrset_list);
	return ret;
}

int ddns_process_update(const zone_t *zone, const knot_pkt_t *query,
                        zone_update_t *update, uint16_t *rcode)
{
	if (zone == NULL || query == NULL || update == NULL || rcode == NULL) {
		if (rcode) {
			*rcode = ret_to_rcode(KNOT_EINVAL);
		}
		return KNOT_EINVAL;
	}

	changeset_t *changeset = update->change;

	if (changeset->soa_from == NULL) {
		// Copy base SOA RR.
		changeset->soa_from =
			node_create_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
		if (changeset->soa_from == NULL) {
			*rcode = ret_to_rcode(KNOT_ENOMEM);
			return KNOT_ENOMEM;
		}
	}

	int64_t sn_old = zone_contents_serial(zone->contents);

	// Process all RRs in the authority section.
	int apex_ns_rem = 0;
	const knot_pktsection_t *authority = knot_pkt_section(query, KNOT_AUTHORITY);
	const knot_rrset_t *authority_rr = knot_pkt_rr(authority, 0);
	for (uint16_t i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = &authority_rr[i];
		// Check if RR is correct.
		int ret = check_update(rr, query, rcode);
		if (ret != KNOT_EOK) {
			assert(*rcode != KNOT_RCODE_NOERROR);
			return ret;
		}

		if (skip_soa(rr, sn_old)) {
			continue;
		}

		ret = process_rr(rr, zone->contents, changeset, &apex_ns_rem);
		if (ret != KNOT_EOK) {
			*rcode = ret_to_rcode(ret);
			return ret;
		}
	}

	if (changeset->soa_to == NULL) {
		// No SOA in the update, create according to current policy
		if (changeset_empty(changeset)) {
			*rcode = KNOT_RCODE_NOERROR;
			// No change, no new SOA
			return KNOT_EOK;
		}

		knot_rrset_t *soa_cpy = knot_rrset_copy(changeset->soa_from, NULL);
		if (soa_cpy == NULL) {
			*rcode = ret_to_rcode(KNOT_ENOMEM);
			return KNOT_ENOMEM;
		}

		conf_val_t val = conf_zone_get(conf(), C_SERIAL_POLICY, zone->name);
		uint32_t old_serial = knot_soa_serial(&soa_cpy->rrs);
		uint32_t new_serial = serial_next(old_serial, conf_opt(&val));
		if (serial_compare(old_serial, new_serial) >= 0) {
			log_zone_warning(zone->name, "updated serial is lower "
			                 "than current, serial %u -> %u",
			                  old_serial, new_serial);
		}

		knot_soa_serial_set(&soa_cpy->rrs, new_serial);
		changeset->soa_to = soa_cpy;
	}

	*rcode = KNOT_RCODE_NOERROR;
	return KNOT_EOK;
}
