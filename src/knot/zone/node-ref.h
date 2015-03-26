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

#include "knot/zone/node-ref.h"
#include "knot/updates/zone-read.h"
#include "knot/dnssec/zone-nsec.h"

enum node_ref_type {
	REF_PREVIOUS = 0,
	REF_PARENT,
	REF_NSEC3
};

typedef struct node_ref {
	zone_node_t *n;
	size_t count;
	uint8_t flags;
} node_ref_t;

void fix_additional_refs(knot_rrset_t *rr, zone_read_t *zone_reader);
bool node_ref_valid(node_ref_t *ref);
struct zone_node *node_ref_get(const struct zone_node *n, enum node_ref_type type, zone_read_t *zone_reader);
struct zone_node *node_ref_get_nsec3(const struct zone_node *n, enum node_ref_type type, zone_read_t *zone_reader);
node_ref_t *node_ref_new(struct zone_node *n);
void node_ref_release(node_ref_t *ref);
void node_ref_invalidate(node_ref_t *ref);

