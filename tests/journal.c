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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <tap/basic.h>

#include "knot/server/journal.h"
#include "knot/zone/zone.h"
#include "knot/zone/zone-diff.h"

#define RAND_RR_LABEL 16
#define RAND_RR_PAYLOAD 64
#define MIN_SOA_SIZE 22

/*! \brief Generate random string with given length. */
static int randstr(char* dst, size_t len)
{
	for (int i = 0; i < len - 1; ++i) {
		dst[i] = '0' + (int) (('Z'-'0') * (rand() / (RAND_MAX + 1.0)));
	}
	dst[len - 1] = '\0';

	return 0;
}

/*! \brief Init RRSet with type SOA and given serial. */
static void init_soa(knot_rrset_t *rr, const uint32_t serial, const knot_dname_t *apex)
{
	knot_rrset_init(rr, knot_dname_copy(apex, NULL), KNOT_RRTYPE_SOA, KNOT_CLASS_IN);

	assert(serial < 256);
	uint8_t soa_data[MIN_SOA_SIZE] = { 0, 0, 0, 0, 0, serial };
	int ret = knot_rrset_add_rdata(rr, soa_data, sizeof(soa_data), 3600, NULL);
	assert(ret == KNOT_EOK);
}

/*! \brief Init RRSet with type TXT, random owner and random payload. */
static void init_random_rr(knot_rrset_t *rr , const knot_dname_t *apex)
{
	/* Create random label. */
	char owner[RAND_RR_LABEL + knot_dname_size(apex)];
	owner[0] = RAND_RR_LABEL - 1;
	randstr(owner + 1, RAND_RR_LABEL);

	/* Append zone apex. */
	memcpy(owner + RAND_RR_LABEL, apex, knot_dname_size(apex));
	knot_rrset_init(rr, knot_dname_copy((knot_dname_t *)owner, NULL), KNOT_RRTYPE_TXT, KNOT_CLASS_IN);

	/* Create random RDATA. */
	uint8_t txt[RAND_RR_PAYLOAD + 1];
	txt[0] = RAND_RR_PAYLOAD - 1;
	randstr((char *)(txt + 1), RAND_RR_PAYLOAD);

	int ret = knot_rrset_add_rdata(rr, txt, RAND_RR_PAYLOAD, 3600, NULL);
	assert(ret == KNOT_EOK);
}

/*! \brief Init changeset with random changes. */
static void init_random_changeset(changeset_t *ch, const uint32_t from, const uint32_t to, const size_t size, const knot_dname_t *apex)
{
	int ret = changeset_init(ch, apex);
	assert(ret == KNOT_EOK);
	
	// Add SOAs
	knot_rrset_t soa;
	init_soa(&soa, from, apex);
	
	ch->soa_from = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_from);
	knot_rrset_clear(&soa, NULL);
	
	init_soa(&soa, to, apex);
	ch->soa_to = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_to);
	knot_rrset_clear(&soa, NULL);
	
	// Add RRs to add section
	for (size_t i = 0; i < size / 2; ++i) {
		knot_rrset_t rr;
		init_random_rr(&rr, apex);
		int ret = changeset_add_rrset(ch, &rr);
		assert(ret == KNOT_EOK);
		knot_rrset_clear(&rr, NULL);
	}

	// Add RRs to remove section
	for (size_t i = 0; i < size / 2; ++i) {
		knot_rrset_t rr;
		init_random_rr(&rr, apex);
		int ret = changeset_rem_rrset(ch, &rr);
		assert(ret == KNOT_EOK);
		knot_rrset_clear(&rr, NULL);
	}
}

/*! \brief Compare two changesets for equality. */
static bool changesets_eq(const changeset_t *ch1, changeset_t *ch2)
{
	if (changeset_size(ch1) != changeset_size(ch2)) {
		return false;
	}

	changeset_iter_t it1;
	changeset_iter_all(&it1, ch1, true);
	changeset_iter_t it2;
	changeset_iter_all(&it2, ch2, true);

	knot_rrset_t rr1 = changeset_iter_next(&it1);
	knot_rrset_t rr2 = changeset_iter_next(&it2);
	bool ret = true;
	while (!knot_rrset_empty(&rr1)) {
		if (!knot_rrset_equal(&rr1, &rr2, KNOT_RRSET_COMPARE_WHOLE)) {
			ret = false;
			break;
		}
		rr1 = changeset_iter_next(&it1);
		rr2 = changeset_iter_next(&it2);
	}

	changeset_iter_clear(&it1);
	changeset_iter_clear(&it2);

	return ret;
}

/*! \brief Test behavior with real changesets. */
static void test_store_load(char *jfilename)
{
	const size_t filesize = 1 * 1024 * 1024;
	journal_t *j = journal_open(jfilename, filesize);
	uint8_t *apex = (uint8_t *)"\4test";

	/* Create fake zone. */
	conf_zone_t zconf;// = { .ixfr_fslimit = filesize };
	zone_t z = { .name = apex, .conf = &zconf };

	/* Save and load changeset. */
	changeset_t ch;
	init_random_changeset(&ch, 0, 1, 128, apex);
	int ret = journal_store_changeset(j, &ch);
	ok(ret == KNOT_EOK, "journal: store changeset");
	list_t l;
	init_list(&l);
	ret = journal_load_changesets(j, z.name, &l, 0, 1);
	ok(ret == KNOT_EOK && changesets_eq(TAIL(l), &ch), "journal: load changeset");
	changeset_clear(&ch);
	changesets_free(&l);
	init_list(&l);

	/* Fill the journal. */
	ret = KNOT_EOK;
	uint32_t serial = 1;
	for (; ret == KNOT_EOK; ++serial) {
		init_random_changeset(&ch, serial, serial + 1, 128, apex);
		ret = journal_store_changeset(j, &ch);
		changeset_clear(&ch);
	}
	ok(ret == KNOT_EBUSY, "journal: overfill with changesets (%d inserted)", serial);

	/* Load all changesets stored until now. */
	serial--;
	ret = journal_load_changesets(j, z.name, &l, 0, serial);
	changesets_free(&l);
	ok(ret == KNOT_EOK, "journal: load changesets");

	/* Flush the journal. */
	ret = journal_mark_synced(j);
	ok(ret == KNOT_EOK, "journal: flush");
	
	/* Store next changeset. */
	init_random_changeset(&ch, serial, serial + 1, 128, apex);
	ret = journal_store_changeset(j, &ch);
		changeset_clear(&ch);
	ok(ret == KNOT_EOK, "journal: store after flush");

	/* Load last changesets. */
	init_list(&l);
	ret = journal_load_changesets(j, z.name, &l, serial, serial + 1);
	changesets_free(&l);
	ok(ret == KNOT_EOK, "journal: load changesets after flush");
	
	journal_close(&j);
}

/*! \brief Test behavior when writing to jurnal and flushing it. */
static void test_stress(char * jfilename)
{
	uint8_t *apex = (uint8_t *)"\4test";
	const size_t filesize = 1 * 1024 * 1024;
	journal_t *j = journal_open(jfilename, filesize);
	int ret = KNOT_EOK;
	uint32_t serial = 0;
	size_t update_size = 2000;
	for (; ret == KNOT_EOK && serial < 250; ++serial) {
		changeset_t ch;
		init_random_changeset(&ch, serial, serial + 1, update_size, apex);
		update_size *= 1.5;
		ret = journal_store_changeset(j, &ch);
		changeset_clear(&ch);
		journal_mark_synced(j);
	}
	ok(ret == KNOT_EBUSY, "journal: does not overfill under load");
	
	journal_close(&j);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Create tmpdir */
	size_t fsize = 10 * 1024 * 1024;
	char *tmpdir = test_tmpdir();
	char jfilename[256];
	snprintf(jfilename, sizeof(jfilename), "%s/%s", tmpdir, "journal.XXXXXX");
	
	/* Create tmpdir */
	mkdtemp(jfilename);
	ok(errno == 0, "make temporary directory '%s'", jfilename);

	/* Try to open journal with too small fsize. */
	/* NOT SUPPORTED */
	journal_t *journal = journal_open(jfilename, 1024);
	ok(journal == NULL, "journal: open too small");

	/* Open/create new journal. */
	journal = journal_open(jfilename, fsize);
	ok(journal != NULL, "journal: open journal '%s'", jfilename);
	if (journal == NULL) {
		goto skip_all;
	}

	
	
	/* Close journal. */
	journal_close(&journal);

	/* Delete journal. */
	//char cmd[256];
	//snprintf(cmd, sizeof(cmd), "rm -rf %s", jfilename);
	//system(cmd);

	test_store_load(jfilename);
	//system(cmd);

	test_stress(jfilename);
	//system(cmd);

	free(tmpdir);

skip_all:
	return 0;
}
