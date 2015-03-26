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

#include <assert.h>

#include "knot/updates/zone-update.h"
#include "knot/updates/changesets.h"
#include "knot/zone/adjust.h"
#include "knot/updates/apply.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zonefile.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-sign.h"
#include "libknot/internal/lists.h"
#include "libknot/internal/mempool.h"
#include "libknot/rrtype/soa.h"

static bool nodes_equal(const zone_node_t *node_a, const zone_node_t *node_b)
{
	if (node_a->rrset_count != node_b->rrset_count) {
		return false;
	}

	for (uint16_t i = 0; i < node_a->rrset_count; ++i) {
		knot_rrset_t rrset_a = node_rrset_at(node_a, i);
		if (!node_rrtype_exists(node_b, rrset_a.type)) {
			return false;
		}
		knot_rrset_t rrset_b = node_rrset(node_b, rrset_a.type);
		if (knot_rdataset_eq(&rrset_a.rrs, &rrset_b.rrs)) {
			return true;
		}
	}

	return false;
}

/*! \brief returns previous node for the same 'level' in the DNS tree. */
static const zone_node_t *get_next_child(zone_update_t *update, const knot_dname_t *owner)
{
	const zone_contents_t *old_zone = update->zone->contents;
	const zone_node_t *prev = zone_contents_find_previous_for_type(old_zone, owner, KNOT_RRTYPE_ANY);
	assert(prev);
	const int owner_labels = knot_dname_labels(owner, NULL);
	if (knot_dname_matched_labels(prev->owner, owner) == owner_labels - 1) {
		return prev;
	} else {
		// No more data for this level.
		return NULL;
	}
}

// TODO: this is too complicated, a way to set an iteration to certain point in zone would solve this much more easily
static bool subtree_removed(zone_update_t *update, const knot_dname_t *cut)
{
#warning trace this, or unittest
	const zone_node_t *gr_child = zone_contents_greatest_child(update->zone->contents, cut);
	if (gr_child == NULL) {
		// If we got to the end of recursion, the subtree is a match.
		return true;
	}

	const zone_node_t *zone_node = gr_child;
	while (zone_node) {
		// Get zone node counterpart in the remove section of changeset.
		const zone_contents_t *remove_part = update->zone->contents;
		const zone_node_t *del_node =
			zone_contents_find_node_for_type(remove_part, zone_node->owner,
			                                 KNOT_RRTYPE_ANY);
		if (del_node == NULL) {
			return false;
		}
		if (!nodes_equal(del_node, zone_node)) {
			return false;
		}
		if (!subtree_removed(update, zone_node->owner)) {
			return false;
		}
		zone_node = get_next_child(update, zone_node->owner);
	}

	return true;
}

static bool node_is_empty_nonterminal(zone_update_t *update, const zone_node_t *node)
{
	if (node->rrset_count > 0) {
		// Node is not empty
		return false;
	}

	if (update->flags & UPDATE_FULL) {
		return zone_contents_has_children(update->new_cont, node->owner);
	}

	assert(update->flags & UPDATE_INCREMENTAL);
	if (zone_contents_has_children(update->change.add, node->owner)) {
		// Added new children for this node, must be empty non-terminal.
		return true;
	}

	// For this node to be empty non-terminal, the whole subtree has to be eventually removed.
	return subtree_removed(update, node->owner);
}

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

static int init_incremental(zone_update_t *update, zone_t *zone)
{
	int ret = changeset_init(&update->change, zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(zone->contents);
	update->new_cont = zone->contents;
	
	return KNOT_EOK;
}

static int init_full(zone_update_t *update, zone_t *zone)
{
	update->new_cont = zone_contents_new(zone->name);
	if (update->new_cont == NULL) {
		return KNOT_ENOMEM;
	}
	
	return KNOT_EOK;
}

static const zone_node_t *get_node(const zone_contents_t *cont, const knot_dname_t *dname, const uint16_t type)
{
	return zone_contents_find_node_for_type(cont, dname, type);
}

static int add_rrsets_to_zone(zone_contents_t *zone, const zone_node_t *node)
{
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		int ret = zone_contents_add_rr(zone, &rrset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static void clear_stored_node(zone_contents_t *temp_nodes,
                              const knot_dname_t *owner,
                              const uint16_t type)
{
	zone_node_t *stored_node = zone_contents_find_node_for_type(temp_nodes, owner, type);
	if (stored_node) {
		node_free_rrsets(stored_node, &temp_nodes->mm);
		zone_tree_t *t = type == KNOT_RRTYPE_NSEC3 ?
		                         temp_nodes->nsec3_nodes : temp_nodes->nodes;
		zone_contents_delete_empty_node(temp_nodes, t, stored_node);
	}
}

static const zone_node_t *temp_nodes_get(zone_update_t *update,
                                         zone_node_t *synth_node,
                                         mm_ctx_t *mm,
                                         const uint16_t type)
{
	const knot_dname_t *key = synth_node->owner;
	zone_contents_t *temp_nodes = update->synth_nodes;
	if (synth_node->rrset_count == 0 &&
	    !node_is_empty_nonterminal(update, synth_node)) {
		// Node deleted, clear possibly stored data from temp zone.
		clear_stored_node(temp_nodes, key, type);
		node_free(&synth_node, NULL);
		return NULL;
	}

	zone_node_t *stored_node = zone_contents_find_node_for_type(temp_nodes, key, type);
	if (stored_node) {
		if (nodes_equal(stored_node, synth_node)) {
			node_free_rrsets(synth_node, mm);
			node_free(&synth_node, mm);
		} else {
			// Free old node contents, replace with new.
			node_free_rrsets(stored_node, mm);
			stored_node->rrs = synth_node->rrs;
			synth_node->rrs = NULL;
			node_free(&synth_node, mm);
		}

		return stored_node;
	}
	
	int ret = add_rrsets_to_zone(temp_nodes, synth_node);
	node_free_rrsets(synth_node, mm);
	node_free(&synth_node, mm);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	return zone_contents_find_node_for_type(temp_nodes, key, type);
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

const zone_node_t *zone_update_get_node(zone_update_t *update, const knot_dname_t *dname,
                                        const uint16_t type)
{
	if (update == NULL || dname == NULL) {
		return NULL;
	}

	const zone_node_t *old_node = get_node(update->new_cont, dname, type);
	if (update->flags & UPDATE_FULL) {
		// No changeset, no changes.
		return old_node;
	}
	
	const zone_node_t *add_node = get_node(update->change.add, dname, type);
	const zone_node_t *rem_node = get_node(update->change.remove, dname, type);
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

	return temp_nodes_get(update, synth_node, &update->mm, type);
}

const zone_node_t *zone_update_get_prev(zone_update_t *update, const knot_dname_t *dname, const uint16_t qtype)
{
	if (update->flags & UPDATE_FULL) {
		return zone_contents_find_previous_for_type(update->new_cont,
		                                            dname, qtype);
	}

	const knot_dname_t *zone_prev =
		zone_contents_find_previous_for_type(update->zone->contents,
		                                     dname, qtype)->owner;
	const knot_dname_t *add_prev =
		zone_contents_find_previous_for_type(update->change.add,
		                                     dname, qtype)->owner;
	if (knot_dname_cmp(zone_prev, add_prev) >= 0) {
		// No greater previous node was added.
		const zone_node_t *synth_prev = zone_update_get_node(update, zone_prev, qtype);
		if (synth_prev) {
			return synth_prev;
		} else {
			// Previous from old zone got deleted, try next previous.
			return zone_update_get_prev(update, zone_prev, qtype);
		}
	} else {
		// Greater previous was added.
		const zone_node_t *synth_prev = zone_update_get_node(update, add_prev, qtype);
		/* 
		 * There *must* be data in the synthesized node, no matter
		 * the deletions: there cannot be such a change, so that
		 * data are added and deleted in the same update, the changeset
		 * structure takes care of that.
		 */
		assert(synth_prev);
		return synth_prev;
	}
}

const zone_node_t *zone_update_get_apex(zone_update_t *update)
{
	return zone_update_get_node(update, update->zone->name, KNOT_RRTYPE_SOA);
}

bool zone_update_has_children(zone_update_t *update, const knot_dname_t *parent)
{
	if (update->flags & UPDATE_FULL) {
		return zone_contents_has_children(update->zone->contents, parent);
	} else {
		if (knot_dname_size(parent) + 2 > KNOT_DNAME_MAXLEN) {
			// Not enough space for children.
			return false;
		}

		knot_dname_t dn[KNOT_DNAME_MAXLEN] = { 0x01, 0xff };
		knot_dname_to_wire(dn + 2, parent, KNOT_DNAME_MAXLEN);
		const zone_node_t *child = zone_update_get_node(update, dn, KNOT_RRTYPE_ANY);
		if (child) {
			return true;
		}

		child = zone_update_get_prev(update, dn, KNOT_RRTYPE_ANY);
		assert(child);
		const int parent_labels = knot_dname_labels(parent, NULL);
		const int child_labels = knot_dname_labels(child->owner, NULL);
		if (child_labels <= parent_labels) {
			return false;
		}

		if (knot_dname_matched_labels(parent, child->owner) != parent_labels) {
			return false;
		}

		return true;
	}
}

static const zone_node_t *get_parent(zone_update_t *update, const knot_dname_t *owner)
{
	const knot_dname_t *par_owner = knot_wire_next_label(owner, NULL);
	if (par_owner == NULL) {
		return NULL;
	}

	return zone_update_get_node(update, par_owner, KNOT_RRTYPE_ANY);
}

bool zone_update_node_is_nonauth(zone_update_t *update, const knot_dname_t *owner)
{
	const zone_node_t *parent = get_parent(update, owner);
	if (parent == NULL) {
		// No parent means we've reached the top of zone hierarchy.
		return false;
	}

	if (node_is_deleg(parent)) {
		return true;
	} else {
		return zone_update_node_is_nonauth(update, parent->owner);
	}
}

uint32_t zone_update_current_serial(zone_update_t *update)
{
	const zone_node_t *apex = zone_update_get_apex(update);
	if (apex) {
		return knot_soa_serial(node_rdataset(apex, KNOT_RRTYPE_SOA));
	} else {
		return 0;
	}
}

const knot_rdataset_t *zone_update_from(zone_update_t *update)
{
	const zone_node_t *apex = update->zone->contents->apex;
	return node_rdataset(apex, KNOT_RRTYPE_SOA);
}

const knot_rdataset_t *zone_update_to(zone_update_t *update)
{
	return &update->change.soa_to->rrs;
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

static bool dnskey_nsec3param_changed(zone_update_t *update)
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
	                       dnskey_nsec3param_changed(update);
	if (full_sign) {
		int ret = knot_dnssec_zone_sign(update, update->zone->conf, 0, &refresh_at);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		int ret = knot_dnssec_sign_changeset(update, update->zone->conf, &refresh_at);
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
	if (update->flags & UPDATE_WRITING_ITER) {
		return changeset_add_rrset(&update->iteration_changes, rrset);
	} else if (update->flags & UPDATE_INCREMENTAL) {
		return changeset_add_rrset(&update->change, rrset);
	} else if (update->flags & UPDATE_FULL) {
		return zone_contents_add_rr(update->new_cont, rrset);
	} else {
		return KNOT_EINVAL;
	}
}

int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update->flags & UPDATE_WRITING_ITER) {
		return changeset_rem_rrset(&update->iteration_changes, rrset);
	} else if (update->flags & UPDATE_INCREMENTAL) {
		return changeset_rem_rrset(&update->change, rrset);
	} else {
		// Removing from zone during creation does not make sense.
		return KNOT_EINVAL;
	}
}

static int create_diff(zone_update_t *update)
{
	// Create diff from two zone contents if possible. Only works for full updates.
	assert(update->flags & UPDATE_FULL);
	zone_contents_t *old_contents = update->zone->contents;
	if (!zone_contents_is_empty(old_contents) &&
	    !zone_contents_is_empty(update->new_cont)) {
		int ret = changeset_init(&update->change, update->zone->name);
		if (ret != KNOT_EOK) {
			return ret;
		}
		ret = zone_contents_diff(old_contents,
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
		*new_contents = update->new_cont;
	} else {
		// Changing live zone - apply with zone copy.
		assert(update->new_cont == NULL);
		int ret = apply_changeset(update->zone, &update->change,
		                          new_contents);
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
#warning try other adjusts
	int ret = zone_adjust_full(update);
	if (ret != KNOT_EOK) {
		if (must_rollback) {
			update_rollback(&update->change);
			update_free_zone(&new_contents);
		}
		return ret;
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

	return KNOT_EOK;
}

static int init_writing_iteration(zone_update_t *update)
{
	if (update->flags & UPDATE_WRITING_ITER) {
		// uncommited change from last writing iteration.
		return KNOT_EAGAIN;
	}

	int ret = changeset_init(&update->iteration_changes, update->zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}

	update->flags |= UPDATE_WRITING_ITER;

	return KNOT_EOK;
}

#define init_iter_with_tree(it, update, tree) \
	memset(it, 0, sizeof(*it)); \
	it->up = update; \
	it->t_it = hattrie_iter_begin(update->zone->contents->tree->db, true); \
	if (it->t_it == NULL) { \
		return KNOT_ENOMEM; \
	} \
	if (update->flags & UPDATE_INCREMENTAL) { \
		it->ch_it = hattrie_iter_begin(update->change.add->tree->db, true); \
		if (it->ch_it == NULL) { \
			hattrie_iter_free(it->t_it); \
			return KNOT_ENOMEM; \
		} \
	} else { \
		it->ch_it = NULL; \
	} \
	return KNOT_EOK;

static int init_iter(zone_update_iter_t *it, zone_update_t *update, const bool read_only, const bool nsec3)
{
	if (!read_only) {
		int ret = init_writing_iteration(update);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (nsec3) {
		init_iter_with_tree(it, update, nsec3_nodes);
	} else {
		init_iter_with_tree(it, update, nodes);
	}
	it->nsec3 = nsec3;
}

int zone_update_iter(zone_update_iter_t *it, zone_update_t *update, const bool read_only)
{
	return init_iter(it, update, read_only, false);
}

int zone_update_iter_nsec3(zone_update_iter_t *it, zone_update_t *update, const bool read_only)
{
	return init_iter(it, update, read_only, true);
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
	const uint16_t qtype = it->nsec3 ? KNOT_RRTYPE_NSEC3 : KNOT_RRTYPE_ANY;
	it->t_node = zone_update_get_node(it->up, n->owner, qtype);
	if (it->t_node == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static void select_smaller_node(zone_update_iter_t *it)
{
#warning this cannot get called if itt is done, but next never returns KNOT_ENOENT
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

static int merge_changeset_part(const changeset_t *from,
                                int (*iter_init)(changeset_iter_t *, const changeset_t *, const bool),
                                changeset_t *to,
                                int (*adder)(changeset_t *, const knot_rrset_t *))
{
	changeset_iter_t itt;
	const bool sorted = false;
	int ret = iter_init(&itt, from, sorted);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t rr = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rr)) {
		int ret = adder(to, &rr);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rr = changeset_iter_next(&itt);
	}

	changeset_iter_clear(&itt);
	return KNOT_EOK;
}

static int merge_changesets(const changeset_t *from, changeset_t *to)
{
	int ret = merge_changeset_part(from, changeset_iter_add, to, changeset_add_rrset);
	if (ret != KNOT_EOK) {
		return ret;
	}
	
	return merge_changeset_part(from, changeset_iter_rem, to, changeset_rem_rrset);
}

int zone_update_iter_finish(zone_update_iter_t *it)
{
	hattrie_iter_free(it->t_it);
	if (!it->up->flags & UPDATE_WRITING_ITER) {
		// No changes during iteration.
		return KNOT_EOK;
	}

	// Clear the flag no matter the outcome, so that retry is possible.
	it->up->flags &= ~UPDATE_WRITING_ITER;

	// Store changes done during the iteration to actual changesets.
	int ret = merge_changesets(&it->up->iteration_changes, &it->up->change);
	changeset_clear(&it->up->iteration_changes);

	return ret;
}

int zone_update_load_contents(zone_update_t *up)
{
	assert(up);
	assert(up->flags & UPDATE_FULL);

	zloader_t zl = { 0 };
	int ret = zonefile_open(&zl, up->zone->conf->file, up->zone->conf->name);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Set the zone type (master/slave). If zone has no master set, we
	 * are the primary master for this zone (i.e. zone type = master).
	 */
	zl.creator->master = !EMPTY_LIST(up->zone->conf->acl.xfr_in);

	ret = zonefile_load(&zl);
	zonefile_close(&zl);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(up->new_cont);
	return KNOT_EOK;
}

bool zone_update_no_change(zone_update_t *up)
{
	return changeset_empty(&up->change);
}

