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

#include "libknot/rrtype/soa.h"

#include "knot/updates/zone-update.h"
#include "knot/updates/changesets.h"
#include "knot/updates/apply.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zonefile.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-sign.h"
#include "common/lists.h"
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

static bool zone_empty(const zone_contents_t *zone)
{
	return zone->nsec3_nodes == NULL && hattrie_weight(zone->nodes) == 1 &&
	       zone->apex->rrset_count == 0;
}

int init_incremental(zone_update_t *update, zone_t *zone)
{
	int ret = changeset_init(&update->change, zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(zone->contents);
	update->new_cont = zone->contents;
}


int init_full(zone_update_t *update, zone_t *zone)
{
	update->new_cont = zone_contents_new(zone->name);
	if (update->new_cont == NULL) {
		return KNOT_ENOMEM;
	}
}

/* ------------------------------- API -------------------------------------- */

int zone_update_init(zone_update_t *update, zone_t *zone, zone_update_flags_t flags)
{
	if (update == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}
	
	memset(update, 0, sizeof(*update));
	update->zone = zone;

	mm_ctx_mempool(&update->mm, 4096);
	update->flags = 0;

	if (flags & UPDATE_INCREMENTAL) {
		return init_incremental(update, zone);
	} else if (flags & UPDATE_FULL) {
		return init_full(update, zone);
	} else {
		// One of FULL or INCREMENTAL flags must be set.
		return KNOT_EINVAL;
	}
}

const zone_node_t *zone_update_get_node(zone_update_t *update, const knot_dname_t *dname)
{
	if (update == NULL || dname == NULL) {
		return NULL;
	}

	const zone_node_t *old_node =
		zone_contents_find_node(update->new_cont, dname);
	if (update->flags & UPDATE_FULL) {
		// No changeset, no changes.
		return old_node;
	}
	
	const zone_node_t *add_node =
		zone_contents_find_node(update->change.add, dname);
	const zone_node_t *rem_node =
		zone_contents_find_node(update->change.remove, dname);

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

const zone_node_t *zone_update_get_apex(zone_update_t *update)
{
	return zone_update_get_node(update, update->zone->name);
}

const zone_node_t *zone_update_serial(zone_update_t *update)
{
	const zone_node_t *apex = zone_update_get_apex(update);
	if (apex) {
		return knot_soa_serial(node_rdataset(apex, KNOT_RRTYPE_SOA));
	} else {
		return 0;
	}
}

void zone_update_clear(zone_update_t *update)
{
	if (update) {
		mp_delete(update->mm.ctx);
		memset(update, 0, sizeof(*update));
	}
}

static bool apex_rr_changed(const zone_node_t *old_apex,
                            const zone_node_t *new_apex,
                            uint16_t type)
{
	knot_rrset_t old_rr = node_rrset(old_apex, type);
	knot_rrset_t new_rr = node_rrset(new_apex, type);

	return !knot_rrset_equal(&old_rr, &new_rr, KNOT_RRSET_COMPARE_WHOLE);
}

static bool dnskey_nsec3param_changed(const zone_update_t *update)
{
	assert(update->zone->contents);
	const zone_node_t *new_apex = zone_update_get_apex(update);
	const zone_node_t *old_apex = update->zone->contents->apex;
	return !changeset_empty(&update->change) &&
	       (apex_rr_changed(new_apex, old_apex, KNOT_RRTYPE_DNSKEY) ||
	        apex_rr_changed(new_apex, old_apex, KNOT_RRTYPE_NSEC3PARAM));
}

static int sign_update(zone_update_t *update)
{
	if (!update->zone->conf->dnssec_enable) {
		return KNOT_EOK;
	}

	uint32_t refresh_at = 0;
	const bool full_sign = changeset_empty(&update->change) ||
	                       dnskey_nsec3param_changed(&update);
	if (full_sign) {
		int ret = dnssec_zone_sign(update, &refresh_at);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		int ret = knot_zone_sign_changeset(update, &refresh_at);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Plan next zone resign.
	const time_t resign_time = zone_events_get_time(update->zone, ZONE_EVENT_DNSSEC);
	if (time(NULL) + refresh_at < resign_time) {
		zone_events_schedule(update->zone, ZONE_EVENT_DNSSEC, refresh_at);
	}

	return KNOT_EOK;
}

int zone_update_add(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update->flags & UPDATE_INCREMENTAL) {
		return changeset_add_rrset(&update->change, rrset);
	} else if (update->flags & UPDATE_FULL) {
		zone_node_t *n;
		return zone_contents_add_rr(update->new_cont, rrset, &n);
	} else {
		return KNOT_EINVAL;
	}
}

int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update->flags & UPDATE_INCREMENTAL) {
		return changeset_rem_rrset(&update->change, rrset);
	} else {
		// Removing from zone during creation does not make sense.
		return KNOT_EINVAL;
	}
}

static int create_diff(zone_update_t *update)
{
	// Create diff from two zone contents if possible.
	zone_contents_t *old_contents = update->zone->contents;
	if (!zone_contents_is_empty(old_contents) &&
	    !zone_contents_is_empty(update->new_cont)) {
		int ret = changeset_init(&update->change, update->zone->name);
		if (ret != KNOT_EOK) {
			return ret;
		}
		ret = zone_contents_create_diff(old_contents,
		                                update->new_cont,
		                                &update->change);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int apply_change(zone_update_t *update, zone_contents_t **new_contents,
                        bool *must_rollback)
{
	if (update->new_cont) {
		// Apply changes directly to new zone.
		int ret = apply_changeset_directly(update->new_cont,
		                                   &update->change);
		if (ret != KNOT_EOK) {
			return ret;
		}
		new_contents = update->new_cont;
	} else {
		// Changing live zone - apply with zone copy.
		assert(update->new_cont == NULL);
		int ret = apply_changeset(update->zone, &update->change,
		                          &new_contents);
		if (ret != KNOT_EOK) {
			return ret;
		}
		*must_rollback = true;
	}
	
	return KNOT_EOK;
}

int zone_update_commit(zone_update_t *update)
{
	if (update->flags & UPDATE_SIGN) {
		int ret = sign_update(update);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	zone_contents_t *new_contents = NULL;
	bool change_made = !changeset_empty(&update->change);
	bool must_rollback = false;
	if (change_made) {
		int ret = apply_change(update, &new_contents, &must_rollback);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else if (update->flags & UPDATE_DIFF) {
		int ret = create_diff(update);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	change_made = !changeset_empty(&update->change);
	if (change_made) {
		// Write received changes / DNSSEC / diff data.
		int ret = zone_change_store(update->zone, &update->change);
		if (ret != KNOT_EOK) {
			if (must_rollback) {
				update_rollback(&update->change);
				update_free_zone(&new_contents);
			}
			return ret;
		}
	}

	// Switch zone contents.
	zone_contents_t *old_contents = NULL;
	if (update->new_cont) {
		old_contents = zone_switch_contents(update->zone, update->new_cont);
	}

	synchronize_rcu();

	if (must_rollback) {
		update_free_zone(&old_contents);
	} else {
		zone_contents_deep_free(&old_contents);
	}

	update_cleanup(&update->change);
	
#warning log update

	return KNOT_EOK;
}

#define init_iter_with_tree(it, update, tree) \
	memset(it, 0, sizeof(*it)); \
	it->up = update; \
	it->t_it = hattrie_iter_begin(update->zone->contents->tree, true); \
	if (it->t_it == NULL) { \
		return KNOT_ENOMEM; \
	} \
	if (update->flags & UPDATE_INCREMENTAL) { \
		it->ch_it = hattrie_iter_begin(update->change.add->tree, true); \
		if (it->ch_it == NULL) { \
			hattrie_iter_free(it->t_it); \
			return KNOT_ENOMEM; \
		} \
	} else { \
		it->ch_it = NULL; \
	} \
	return KNOT_EOK;

int zone_update_iter(zone_update_iter_t *it, zone_update_t *update)
{
	init_iter_with_tree(it, update, nodes);
}

int zone_update_iter_nsec3(zone_update_iter_t *it, zone_update_t *update)
{
	init_iter_with_tree(it, update, nsec3_nodes);
}

static int iter_get_added_node(zone_update_iter_t *it)
{
	if (hattrie_iter_finished(it->ch_it)) {
		hattrie_iter_free(it->ch_it);
		it->ch_it = NULL;
		return KNOT_ENOENT;
	}

	hattrie_iter_next(it->t_it);
	it->ch_node = (zone_node_t *)(*hattrie_iter_val(it->t_it));

	return KNOT_EOK;
}

static int iter_get_synth_node(zone_update_iter_t *it)
{
	if (hattrie_iter_finished(it->t_it)) {
		hattrie_iter_free(it->t_it);
		it->ch_it = NULL;
		return KNOT_ENOENT;
	}

	if (it->t_node) {
		// Don't get next for very first data.
		hattrie_iter_next(it->t_it);
	}

	const zone_node_t *n = (zone_node_t *)(*hattrie_iter_val(it->t_it));
	it->t_node = zone_update_get_node(it->up, n->owner);
	if (it->t_node == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static void select_smaller_node(zone_update_iter_t *it)
{
	if (it->t_node && it->ch_node) {
		// Choose 'smaller' node to return.
		if (knot_dname_cmp(it->t_node->owner, it->ch_node->owner) <= 0) {
			// Return the synthesized node.
			it->next_n = it->t_node;
			it->t_node = NULL;
		} else {
			// Return the new node.
			it->next_n = it->ch_node;
			it->ch_node = NULL;
		}
	}

	// Return the remaining node.
	if (it->t_node) {
		it->next_n = it->t_node;
		it->t_node = NULL;
	} else {
		assert(it->ch_node);
		it->next_n = it->ch_node;
		it->ch_node = NULL;
	}
}

int zone_update_iter_next(zone_update_iter_t *it)
{
	if (it == NULL) {
		return KNOT_EINVAL;
	}

	// Get nodes from both iterators if needed.
	if (it->t_it && it->t_node == NULL) {
		int ret = iter_get_synth_node(it);
		if (ret != KNOT_EOK) {
			if (ret != KNOT_ENOENT) {
				return ret;
			}
		}
	}

	if (it->ch_it && it->ch_node == NULL) {
		int ret = iter_get_added_node(it);
		if (ret != KNOT_EOK) {
			if (ret != KNOT_ENOENT) {
				return ret;
			}
		}
	}

	select_smaller_node(it);
	return KNOT_EOK;
}

const zone_node_t *zone_update_iter_val(zone_update_iter_t *it)
{
	if (it) {
		return it->next_n;
	} else {
		return NULL;
	}
}

int zone_update_load_contents(zone_update_t *up)
{
	assert(up);
	assert(up->flags & UPDATE_FULL);

	zloader_t zl = { 0 };
	int ret = zonefile_open(&zl, up->zone->conf->file, up->zone->conf->name,
	                        up->zone->conf->enable_checks);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Set the zone type (master/slave). If zone has no master set, we
	 * are the primary master for this zone (i.e. zone type = master).
	 */
	zl.creator->master = !zone_load_can_bootstrap(up->zone->conf);

	zone_contents_t *zone_contents = zonefile_load(&zl);
	zonefile_close(&zl);
	if (zone_contents == NULL) {
		return NULL;
	}

	return zone_contents;
}

