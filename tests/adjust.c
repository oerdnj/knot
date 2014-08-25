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

#include <tap/basic.h>

#include "knot/zone/adjust.h"
#include "knot/zone/zonefile.h"
#include "knot/updates/apply.h"
#include "knot/dnssec/zone-nsec.h"

static const char *zone_str =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"b.test. IN TXT \"test\"\n"
"e.test. IN TXT \"test\"\n"
"x.test. IN TXT \"test\"\n";

static const char *add1 =
"test. 3600 IN SOA a. b. 2 1 1 1 1\n"
"c.test. IN TXT \"test\"\n"
"d.test. IN TXT \"test\"\n";

static const char *switch_nsec3 =
"test. 3600 IN SOA a. b. 3 1 1 1 1\n"
"test. 0 IN NSEC3PARAM 1 0 10 DEADBEEF\n"
"65QBS2TUD2SO2HMDIIFLAQVDHPL7EH56.test. IN NSEC3 1 0 10 DEADBEEF 7B4NC67ERA0FFG0QFHRRDCKH0OK3PESO TXT\n" // d.test.
"7B4NC67ERA0FFG0QFHRRDCKH0OK3PESO.test. IN NSEC3 1 0 10 DEADBEEF R8A5UNFOSHQNDVESUCUULJ8IHQ7N7ID7 SOA NSEC3PARAM\n" // test.
"R8A5UNFOSHQNDVESUCUULJ8IHQ7N7ID7.test. IN NSEC3 1 0 10 DEADBEEF RQPTAJDPMTSC4ADKMOMIA5K3QS1HHKE9 TXT\n" // e.test
"RQPTAJDPMTSC4ADKMOMIA5K3QS1HHKE9.test. IN NSEC3 1 0 10 DEADBEEF 65QBS2TUD2SO2HMDIIFLAQVDHPL7EH56 TXT\n"; // c.test

static const char *add_nsec3=
"test. 3600 IN SOA a. b. 4 1 1 1 1\n"
"f.test. IN TXT \"test\"\n"
"HAPB22MLBPNJTUSSFP5QNIBAQJHPP0VM.test. IN NSEC3 1 0 10 DEADBEEF R8A5UNFOSHQNDVESUCUULJ8IHQ7N7ID7 TXT\n";

static const char *del1 =
"test. 3600 IN SOA a. b. 5 1 1 1 1\n"
"x.test. IN TXT \"test\"\n";

static const char *del2 =
"test. 3600 IN SOA a. b. 6 1 1 1 1\n"
"b.test. IN TXT \"test\"\n"
"x.test. IN TXT \"test\"\n";

static const char *flags_zone = 
"test. 3600 IN SOA a. b. 7 1 1 1 1\n"
"*.test. IN A 5.6.7.8\n"
"ns.test. IN NS ns1\n"
"sub.test. IN NS sub.whatever.\n"
"glue.sub.test. IN A 1.2.3.4\n"
"x.test. IN TXT \"test\"\n";

struct adjust_params {
	zcreator_t *zc;
	changeset_t *ch;
};

static void scanner_process(zs_scanner_t *scanner)
{
	struct adjust_params *params = scanner->data;

	knot_rrset_t rr;
	uint8_t owner[KNOT_DNAME_MAXLEN];
	memcpy(owner, scanner->r_owner, knot_dname_size(scanner->r_owner));
	knot_dname_to_lower(&owner);
	knot_rrset_init(&rr, owner, scanner->r_type, scanner->r_class);
	int ret = knot_rrset_add_rdata(&rr, scanner->r_data, scanner->r_data_length,
	                               scanner->r_ttl, NULL);
	assert(ret == KNOT_EOK);
	if (rr.type == KNOT_RRTYPE_SOA && params->ch) {
		// Store SOA into changeset, do not add to zone.
		knot_rrset_free(&params->ch->soa_to, NULL);
		params->ch->soa_to = knot_rrset_copy(&rr, NULL);
		assert(params->ch->soa_to);
		knot_rdataset_clear(&rr.rrs, NULL);
		return;
	}
	ret = zcreator_step(params->zc, &rr);
	assert(ret == KNOT_EOK);
	knot_rdataset_clear(&rr.rrs, NULL);
}

static bool nsec3_set_ok(zone_node_t *n, zone_contents_t *zone)
{
	if (n->nsec3_node == NULL) {
		diag("NSEC3 node not set");
		return false;
	}
	
	knot_dname_t *nsec3_name =
		knot_create_nsec3_owner(n->owner,
		                        zone->apex->owner,
		                        node_rdataset(zone->apex,
		                                      KNOT_RRTYPE_NSEC3PARAM));
	assert(nsec3_name);
	zone_node_t *found_nsec3 = NULL;
	zone_tree_get(zone->nsec3_nodes, nsec3_name, &found_nsec3);
	assert(found_nsec3);
	
	diag("Found %s for %s, valid %s", knot_dname_to_str(n->nsec3_node->owner),
	     knot_dname_to_str(n->owner), knot_dname_to_str(nsec3_name));
	
	return n->nsec3_node == found_nsec3 && n->nsec3_node->nsec3_node == n;
}

static bool flags_set_ok(zone_node_t *n, zone_contents_t *zone)
{
	uint8_t flags = 0;
	if (knot_dname_is_wildcard(n->owner) && n->parent) {
		flags |= NODE_FLAGS_WILDCARD_CHILD;
	}
	if (knot_
}

// Iterates through the zone and checks previous pointers
static bool test_prev_for_tree(zone_tree_t *t, zone_contents_t *zone)
{
	if (t == NULL) {
		return true;
	}
	
	hattrie_iter_t *itt = hattrie_iter_begin(t, true);
	assert(itt);
	
	zone_node_t *first = (zone_node_t *)(*hattrie_iter_val(itt));
	zone_node_t *prev = NULL;
	zone_node_t *curr = NULL;
	while(!hattrie_iter_finished(itt)) {
		prev = curr;
		curr = (zone_node_t *)(*hattrie_iter_val(itt));
		printf("%s->%s ", knot_dname_to_str(curr->prev->owner),
		       knot_dname_to_str(curr->owner));
		if (prev) {
			if (curr->prev != prev) {
				diag("Prev is not set properly");
				hattrie_iter_free(itt);
				return false;
			}
		}
		
		if (node_rrtype_exists(zone->apex, KNOT_RRTYPE_NSEC3PARAM) &&
		    !node_rrtype_exists(curr, KNOT_RRTYPE_NSEC3)) {
			if (!nsec3_set_ok(curr, zone)) {
				diag("NSEC3 pointer not set properly for %s",
				     knot_dname_to_str(curr->owner));
				hattrie_iter_free(itt);
				return false;
			}
		}
		
		if (!flags_set_ok(curr, zone)) {
			diag("Flags not properly set");
			return false;
		}
		
		hattrie_iter_next(itt);
	}
	
	printf("\n");
	
	hattrie_iter_free(itt);
	return first->prev == curr;
}

static bool test_zone(zone_contents_t *zone)
{
	return test_prev_for_tree(zone->nodes, zone) && test_prev_for_tree(zone->nsec3_nodes, zone);
}

static void add_and_update(zone_contents_t *zone, changeset_t *ch,
                           zs_scanner_t *sc, const char *str)
{
	// Parse record
	int ret = zs_scanner_parse(sc, str, str + strlen(str), true);
	assert(ret == 0);
	knot_rrset_free(&ch->soa_from, NULL);
	ch->soa_from = node_create_rrset(zone->apex, KNOT_RRTYPE_SOA);
	assert(ch->soa_to && ch->soa_from);
	// Insert
	ret = apply_changeset_directly(zone, ch);
	assert(ret == KNOT_EOK);
}

#define TEST_VALIDITY(zone, up, ch, msg) \
	ret = zone_adjust(up); \
	ok(ret == KNOT_EOK && test_zone(zone), msg); \
	changeset_clear(ch); \
	changeset_init(ch, zone->apex->owner);

int main(int argc, char *argv[])
{
	plan(10);
	
	// Fill zone
	knot_dname_t *owner = knot_dname_from_str("test.");
	assert(owner);
	zone_contents_t *zone = zone_contents_new(owner);
	assert(zone);
	zcreator_t zc = {.z = zone, .master = true, .ret = KNOT_EOK };
	struct adjust_params params = {.zc = &zc, .ch = NULL };
	zs_scanner_t *sc = zs_scanner_create("test.", KNOT_CLASS_IN, 3600, scanner_process,
	                                     NULL, &params);
	assert(sc);
	int ret = zs_scanner_parse(sc, zone_str, zone_str + strlen(zone_str), true);
	assert(ret == 0);
	
	// Test full adjust
	zone_update_t up;
	zone_update_init(&up, zone, NULL);
	ret = zone_adjust(&up);
	ok(ret == KNOT_EOK && test_zone(zone), "zone adjust: full adjust");
	
	// Init zone update structure
	changeset_t ch;
	changeset_init(&ch, owner);
	zone_update_init(&up, zone, &ch);
	
	// --- PREV pointer tests
	
	// Add a record
	zc.z = ch.add;
	params.ch = &ch;
	add_and_update(zone, &ch, sc, add1);
	TEST_VALIDITY(zone, &up, &ch, "zone adjust: addition");
	
	// Remove a record
	zc.z = ch.remove;
	add_and_update(zone, &ch, sc, add1);
	TEST_VALIDITY(zone, &up, &ch, "zone adjust: deletion");
	
	// Remove the last record
	zc.z = ch.remove;
	add_and_update(zone, &ch, sc, del1);
	TEST_VALIDITY(zone, &up, &ch, "zone adjust: delete last");
	
	// Add record that will become last
	zc.z = ch.add;
	add_and_update(zone, &ch, sc, del1);
	TEST_VALIDITY(zone, &up, &ch, "zone adjust: add last");
	
	// Add and remove records
	zc.z = ch.add;
	add_and_update(zone, &ch, sc, add1);
	zc.z = ch.remove;
	add_and_update(zone, &ch, sc, del2);
	TEST_VALIDITY(zone, &up, &ch, "zone adjust: add and remove");
	
	// --- NSEC3 tests
	
	// Add all NSEC3 records
	zc.z = ch.add;
	add_and_update(zone, &ch, sc, switch_nsec3);
	TEST_VALIDITY(zone, &up, &ch, "zone adjust: switch NSEC3");
	
	// Add new record and its NSEC3
	zc.z = ch.add;
	add_and_update(zone, &ch, sc, add_nsec3);
	TEST_VALIDITY(zone, &up, &ch, "zone adjust: add NSEC3");
	
	// Remove previously added NSEC3
	zc.z = ch.remove;
	add_and_update(zone, &ch, sc, add_nsec3);
	TEST_VALIDITY(zone, &up, &ch, "zone adjust: remove NSEC3");
	
	// --- FLAGS tests
	
	zone_contents_deep_free(&zone);
	// Reset zone
	zone = zone_contents_new(owner);
	assert(zone);
	zc.z = zone;
	params.ch = NULL;
	ret = zs_scanner_parse(sc, flags_zone, flags_zone + strlen(flags_zone), true);
	assert(ret == 0);
	TEST_VALIDITY(zone, &up, &ch, "zone adjust: flags");
	
	return 0;
}
