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

#include "knot/updates/zone-update.h"
#include "common-knot/lists.h"
#include "common/mempool.h"

static int add_to_node(zone_node_t *node, const zone_node_t *add_node,
                       mm_ctx_t *mm)
{
	for (uint16_t i = 0; i < add_node->rrset_count; ++i) {
		knot_rrset_t rr = node_rrset_at(add_node, i);
		if (!knot_rrset_empty(&rr)) {
			int ret = node_add_rrset(node, &rr, mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

static int rem_from_node(zone_node_t *node, const zone_node_t *rem_node,
                         mm_ctx_t *mm)
{
	for (uint16_t i = 0; i < rem_node->rrset_count; ++i) {
		// Remove each found RR from 'node'.
		knot_rrset_t rem_rrset = node_rrset_at(rem_node, i);
		knot_rdataset_t *to_change = node_rdataset(node, rem_rrset.type);
		if (to_change) {
			// Remove data from synthesized node
			int ret = knot_rdataset_subtract(to_change,
			                                 &rem_rrset.rrs,
			                                 mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

static int apply_changes_to_node(zone_node_t *synth_node, const zone_node_t *add_node,
                                 const zone_node_t *rem_node, mm_ctx_t *mm)
{
	// Add changes to node
	if (!node_empty(add_node)) {
		int ret = add_to_node(synth_node, add_node, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Remove changes from node
	if (!node_empty(rem_node)) {
		int ret = rem_from_node(synth_node, rem_node, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int deep_copy_node_data(zone_node_t *node_copy, const zone_node_t *node,
                               mm_ctx_t *mm)
{
	// Clear space for RRs
	node_copy->rrs = NULL;
	node_copy->rrset_count = 0;
	
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t rr = node_rrset_at(node, i);
		int ret = node_add_rrset(node_copy, &rr, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static zone_node_t *node_deep_copy(const zone_node_t *node, mm_ctx_t *mm)
{
	// Shallow copy old node
	zone_node_t *synth_node = node_shallow_copy(node, mm);
	if (synth_node == NULL) {
		return NULL;
	}

	// Deep copy data inside node copy.
	int ret = deep_copy_node_data(synth_node, node, mm);
	if (ret != KNOT_EOK) {
		node_free(&synth_node, mm);
		return NULL;
	}

	return synth_node;
}

static bool zone_empty(zone)
{
	return zone->nsec3_nodes == NULL && hattrie_weight(zone->nodes) == 1 &&
	       zone->apex->rrset_count == 0;
}

/* ------------------------------- API -------------------------------------- */

int zone_update_init(zone_update_t *update, zone_t *zone, zone_update_flags_t flags)
{
	if (update == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}
	
	memset(update, 0, sizeof(*update));
	update->zone = zone;
	
	if (flags & UPDATE_INCREMENTAL) {
		int ret = changeset_init(&update->change, zone->name);
		if (ret != KNOT_EOK) {
			return ret;
		}
		assert(zone->contents);
		update->c = zone->contents;
	} else if (flags & UPDATE_FULL) {
		update->c = zone_contents_new(zone->name);
		if (update->c == NULL) {
			return KNOT_ENOMEM;
		}
	}
	
	mm_ctx_mempool(&update->mm, 4096);
	update->flags = 0;
	
	return KNOT_EOK;
}

const zone_node_t *zone_update_get_node(zone_update_t *update, const knot_dname_t *dname)
{
	if (update == NULL || dname == NULL) {
		return NULL;
	}

	const zone_node_t *old_node =
		zone_contents_find_node(update->c, dname);
	if (update->flags & UPDATE_FULL) {
		// No changeset, no changes.
		return old_node;
	}
	
	const zone_node_t *add_node =
		zone_contents_find_node(update->change->add, dname);
	const zone_node_t *rem_node =
		zone_contents_find_node(update->change->remove, dname);

	const bool have_change = !node_empty(add_node) || !node_empty(rem_node);
	if (!have_change) {
		// Nothing to apply
		return old_node;
	}

	if (!old_node) {
		if (add_node && node_empty(rem_node)) {
			// Just addition
			return add_node;
		} else {
			// Addition and deletion
			old_node = add_node;
			add_node = NULL;
		}
	}

	// We have to apply changes to node.
	zone_node_t *synth_node = node_deep_copy(old_node, &update->mm);
	if (synth_node == NULL) {
		return NULL;
	}

	// Apply changes to node.
	int ret = apply_changes_to_node(synth_node, add_node, rem_node,
	                                &update->mm);
	if (ret != KNOT_EOK) {
		node_free_rrsets(synth_node, &update->mm);
		node_free(&synth_node, &update->mm);
		return NULL;
	}

	return synth_node;
}

void zone_update_clear(zone_update_t *update)
{
	if (update) {
		mp_delete(update->mm.ctx);
		memset(update, 0, sizeof(*update));
	}
}

static bool apex_rr_changed(const zone_contents_t *old_contents,
                            const zone_contents_t *new_contents,
                            uint16_t type)
{
	knot_rrset_t old_rr = node_rrset(old_contents->apex, type);
	knot_rrset_t new_rr = node_rrset(new_contents->apex, type);

	return !knot_rrset_equal(&old_rr, &new_rr, KNOT_RRSET_COMPARE_WHOLE);
}

static int sign_update(zone_t *zone, const zone_contents_t *old_contents,
                       zone_contents_t *new_contents, changeset_t *ddns_ch,
                       changeset_t *sec_ch)
{
	assert(zone != NULL);
	assert(old_contents != NULL);
	assert(new_contents != NULL);
	assert(ddns_ch != NULL);

	/*
	 * Check if the UPDATE changed DNSKEYs or NSEC3PARAM.
	 * If so, we have to sign the whole zone.
	 */
	int ret = KNOT_EOK;
	uint32_t refresh_at = 0;
	if (apex_rr_changed(old_contents, new_contents, KNOT_RRTYPE_DNSKEY) ||
	    apex_rr_changed(old_contents, new_contents, KNOT_RRTYPE_NSEC3PARAM)) {
		ret = knot_dnssec_zone_sign(new_contents, zone->conf,
		                            sec_ch, KNOT_SOA_SERIAL_KEEP,
		                            &refresh_at);
	} else {
		// Sign the created changeset
		ret = knot_dnssec_sign_changeset(new_contents, zone->conf,
		                                 ddns_ch, sec_ch,
		                                 &refresh_at);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Apply DNSSEC changeset
	ret = apply_changeset_directly(new_contents, sec_ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Merge changesets
	ret = changeset_merge(ddns_ch, sec_ch);
	if (ret != KNOT_EOK) {
		update_cleanup(sec_ch);
		return ret;
	}

	// Plan next zone resign.
	const time_t resign_time = zone_events_get_time(zone, ZONE_EVENT_DNSSEC);
	if (time(NULL) + refresh_at < resign_time) {
		zone_events_schedule(zone, ZONE_EVENT_DNSSEC, refresh_at);
	}

	return KNOT_EOK;
}

static int sign_change(zone_update_t *update)
{
	
}

int zone_update_add(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update->flags & UPDATE_INCREMENTAL) {
		return changeset_add_rrset(update->change, rrset);
	} else if (update->flags & UPDATE_FULL) {
		zone_node_t *n;
		return zone_contents_add_rr(update->zone, rrset, &n);
	} else {
		return KNOT_EINVAL;
	}
}

int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update->flags & UPDATE_INCREMENTAL) {
		return changeset_rem_rrset(update->change, rrset);
	} else {
		// Removing from zone during creation does not make sense.
		return KNOT_EINVAL;
	}
}

int zone_update_commit(zone_update_t *update)
{
	if (update->flags & UPDATE_SIGN) {
		int ret = sign_change(update);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}
	
	if (update->flags & UPDATE_FULL) {
		zone_contents_t *old_contents =
		                zone_switch_contents(zone, update->c);
		synchronize_rcu();
		
		zone_contents_deep_free(&old_contents);
		return KNOT_EOK;
	} else if (update->flags & UPDATE_INCREMENTAL) {
		const bool change_made = !changeset_empty(&update->change);
		if (!change_made) {
			return KNOT_EOK;
		}
		
		zone_contents_t *new_contents;
		int ret = apply_changeset(update->zone, update->change, &new_contents);
		if (ret != KNOT_EOK) {
			return ret;
		}
	
		ret = zone_change_store(update->zone, update->change);
		if (ret != KNOT_EOK) {
			update_rollback(&update->change);
			update_free_zone(&new_contents);
			return ret;
		}
	
		zone_contents_t *old_contents = zone_switch_contents(update->zone,
		                                                     new_contents);
		synchronize_rcu();
		
		update_free_zone(&old_contents);
		update_cleanup(&update->change);
	} else {
		return KNOT_EINVAL;
	}
}
