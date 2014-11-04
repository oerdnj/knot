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

#include "shared.h"
#include "error.h"
#include "kasp.h"
#include "kasp/internal.h"

/* -- internal API --------------------------------------------------------- */

int dnssec_kasp_create(dnssec_kasp_t **kasp_ptr,
                       const dnssec_kasp_store_functions_t *functions)
{
	if (!kasp_ptr || !functions) {
		return DNSSEC_EINVAL;
	}

	dnssec_kasp_t *kasp = malloc(sizeof(*kasp));
	if (!kasp) {
		return DNSSEC_ENOMEM;
	}

	clear_struct(kasp);
	kasp->functions = functions;

	*kasp_ptr = kasp;
	return DNSSEC_EOK;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_kasp_init(dnssec_kasp_t *kasp, const char *config)
{
	if (!kasp || !config) {
		return DNSSEC_EINVAL;
	}

	return kasp->functions->init(config);
}

_public_
void dnssec_kasp_deinit(dnssec_kasp_t *kasp)
{
	if (!kasp) {
		return;
	}

	dnssec_kasp_close(kasp);
	free(kasp);
}

_public_
int dnssec_kasp_open(dnssec_kasp_t *kasp, const char *config)
{
	if (!kasp || !config) {
		return DNSSEC_EINVAL;
	}

	return kasp->functions->open(&kasp->ctx, config);
}

_public_
void dnssec_kasp_close(dnssec_kasp_t *kasp)
{
	if (!kasp) {
		return;
	}

	if (kasp->ctx) {
		kasp->functions->close(kasp->ctx);
		kasp->ctx = NULL;
	}
}

_public_
int dnssec_kasp_zone_load(dnssec_kasp_t *kasp, const char *zone_name,
			 dnssec_kasp_zone_t **zone_ptr)
{
	if (!kasp || !zone_name || !zone_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_kasp_zone_t *zone = dnssec_kasp_zone_new(zone_name);
	if (!zone) {
		return DNSSEC_ENOMEM;
	}

	int result = kasp->functions->zone_load(kasp->ctx, zone);
	if (result != DNSSEC_EOK) {
		dnssec_kasp_zone_free(zone);
		return result;
	}

	*zone_ptr = zone;
	return DNSSEC_EOK;
}

_public_
int dnssec_kasp_zone_save(dnssec_kasp_t *kasp, dnssec_kasp_zone_t *zone)
{
	if (!kasp || !zone) {
		return DNSSEC_EINVAL;
	}

	return kasp->functions->zone_save(kasp->ctx, zone);
}

_public_
int dnssec_kasp_zone_remove(dnssec_kasp_t *kasp, const char *zone_name)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

_public_
int dnssec_kasp_zone_list(dnssec_kasp_t *kasp, dnssec_list_t **list_ptr)
{
	if (!kasp || !list_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_list_t *list = dnssec_list_new();
	if (!list) {
		return DNSSEC_ENOMEM;
	}

	int result = kasp->functions->zone_list(kasp->ctx, list);
	if (result != DNSSEC_EOK) {
		dnssec_list_free_full(list, NULL, NULL);
		return result;
	}

	*list_ptr = list;
	return DNSSEC_EOK;
}