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

#include "knot/updates/ddns.h"
#include "knot/updates/changesets.h"
#include "knot/updates/zone-update.h"
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

	if (!knot_dname_in(update->zone->name, rrset->owner)) {
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

/*!< \brief Used to ignore SOA deletions and SOAs with lower serial than zone. */
static bool skip_soa(const knot_rrset_t *rr, const uint32_t sn)
{
	if (rr->type == KNOT_RRTYPE_SOA &&
	    (rr->rclass == KNOT_CLASS_NONE || rr->rclass == KNOT_CLASS_ANY ||
	     serial_compare(knot_soa_serial(&rr->rrs), sn) <= 0)) {
		return true;
	}

	return false;
}

/* ------------------------ RR processing logic ----------------------------- */

/* --------------------------- RR additions --------------------------------- */

/*!< \brief Adds normal RR, ignores when CNAME exists in node. */
static int process_add_normal(const zone_node_t *node,
                              const knot_rrset_t *rr,
                              zone_update_t *update)
{
	if (node_rrtype_exists(node, KNOT_RRTYPE_CNAME)) {
		// Adding RR to CNAME node, ignore.
		return KNOT_EOK;
	}

	return zone_update_add(update, rr);
}

/* --------------------------- RR deletions --------------------------------- */

/*!< \brief Removes single RR from zone. */
static int process_rem_rr(const knot_rrset_t *rr,
                          const zone_node_t *node,
                          zone_update_t *update)
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
		if (ns_rrs->rr_count == 1) {
			// Cannot remove last apex NS RR.
			return KNOT_EOK;
		}
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
	ret = zone_update_remove(update, &intersection);
	knot_rdataset_clear(&intersection.rrs, NULL);
	return ret;
}

/*!< \brief Removes RRSet from zone. */
static int process_rem_rrset(const knot_rrset_t *rrset,
                             const zone_node_t *node,
                             zone_update_t *update)
{
	if (rrset->type == KNOT_RRTYPE_SOA ||
	    knot_rrtype_is_ddns_forbidden(rrset->type)) {
		// Ignore SOA and DNSSEC removals.
		return KNOT_EOK;
	}

	if (node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	    rrset->type == KNOT_RRTYPE_NS) {
		// Ignore NS apex RRSet removals.
		return KNOT_EOK;
	}

	if (node == NULL) {
		// no such node in zone, ignore
		return KNOT_EOK;
	}

	if (!node_rrtype_exists(node, rrset->type)) {
		// no such RR, ignore
		return KNOT_EOK;
	}

	knot_rrset_t to_remove = node_rrset(node, rrset->type);
	return zone_update_remove(update, &to_remove);
}

/*!< \brief Removes node from zone. */
static int process_rem_node(const knot_rrset_t *rr,
                            const zone_node_t *node, zone_update_t *update)
{
	if (node == NULL) {
		return KNOT_EOK;
	}

	// Remove all RRSets from node
	for (int i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		int ret = process_rem_rrset(&rrset, node, update);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*!< \brief Decides what to with removal. */
static int process_remove(const knot_rrset_t *rr,
                          const zone_node_t *node,
                          zone_update_t *update)
{
	if (is_rr_removal(rr)) {
		return process_rem_rr(rr, node, update);
	} else if (is_rrset_removal(rr)) {
		return process_rem_rrset(rr, node, update);
	} else if (is_node_removal(rr)) {
		return process_rem_node(rr, node, update);
	} else {
		return KNOT_EINVAL;
	}
}

/* --------------------------- validity checks ------------------------------ */

/*!< \brief Checks whether addition has not violated DNAME rules. */
static bool sem_check(const knot_rrset_t *rr,
                      const zone_node_t *zone_node,
                      zone_update_t *update)
{
	// Check that we have not added DNAME child
	const knot_dname_t *parent_dname = knot_wire_next_label(rr->owner, NULL);
	const zone_node_t *parent = zone_update_get_node(update, parent_dname);
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
#warning direct use of contents
	if (zone_contents_has_children(update->zone->contents, zone_node->owner)) {
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

	if (knot_rrtype_is_ddns_forbidden(rrset->type)) {
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
static int process_rr(const knot_rrset_t *rr, zone_update_t *update)
{
	const zone_node_t *node = zone_update_get_node(update, rr->owner);

	if (is_addition(rr)) {
		int ret = process_add_normal(node, rr, update);
		if (ret == KNOT_EOK) {
			if (!sem_check(rr, node, update)) {
				return KNOT_EDENIED;
			}
		}
		return ret;
	} else if (is_removal(rr)) {
		return process_remove(rr, node, update);
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
	for (int i = 0; i < answer->count; ++i) {
		// Check what can be checked, store full RRs into list
		ret = process_prereq(&answer->rr[i], knot_pkt_qclass(query),
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

	uint32_t sn_old = knot_soa_serial(zone_update_from(update));

	// Process all RRs in the authority section.
	const knot_pktsection_t *authority =
	                knot_pkt_section(query, KNOT_AUTHORITY);
	for (uint16_t i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = &authority->rr[i];
		// Check if RR is correct.
		int ret = check_update(rr, query, rcode);
		if (ret != KNOT_EOK) {
			assert(*rcode != KNOT_RCODE_NOERROR);
			return ret;
		}

		if (skip_soa(rr, sn_old)) {
			continue;
		}

		ret = process_rr(rr, update);
		if (ret != KNOT_EOK) {
			*rcode = ret_to_rcode(ret);
			return ret;
		}
	}

	if (zone_update_to(update) == NULL) {
#warning updates SOA everytime for now, I think that's actually okay, but it'd better to check for changes
		// No SOA in the update, create one according to the current policy
		knot_rrset_t old_soa = node_rrset(zone_update_get_apex(update), KNOT_RRTYPE_SOA);
		knot_rrset_t *new_soa = knot_rrset_copy(&old_soa, NULL);
		if (new_soa == NULL) {
			*rcode = ret_to_rcode(KNOT_ENOMEM);
			return KNOT_ENOMEM;
		}

		const uint32_t new_serial = zone_contents_next_serial(zone->contents,
		                               zone->conf->serial_policy);
		knot_soa_serial_set(&new_soa->rrs, new_serial);
		int ret = zone_update_add(update, new_soa);
		knot_rrset_free(&new_soa, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	*rcode = KNOT_RCODE_NOERROR;
	return KNOT_EOK;
}
