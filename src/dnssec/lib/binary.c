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
#include <nettle/base64.h>
#include <string.h>

#include "binary.h"
#include "error.h"
#include "shared.h"

static size_t base64_decode_raw(const uint8_t *src, size_t src_len,
				uint8_t *dst, size_t dst_max_size)
{
	assert(src);
	assert(dst);

	struct base64_decode_ctx ctx;
	base64_decode_init(&ctx);

	unsigned dst_size = dst_max_size;
	int result = base64_decode_update(&ctx, &dst_size, dst, src_len, src);
	if (result != 1) {
		return 0;
	}

	return (size_t) dst_size;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_binary_alloc(dnssec_binary_t *data, size_t size)
{
	if (!data || size == 0) {
		return DNSSEC_EINVAL;
	}

	uint8_t *new_data = calloc(1, size);
	if (!new_data) {
		return DNSSEC_ENOMEM;
	}

	data->data = new_data;
	data->size = size;

	return DNSSEC_EOK;
}

_public_
void dnssec_binary_free(dnssec_binary_t *binary)
{
	if (!binary) {
		return;
	}

	free(binary->data);
	clear_struct(binary);
}

_public_
int dnssec_binary_dup(const dnssec_binary_t *from, dnssec_binary_t *to)
{
	if (!from || !to) {
		return DNSSEC_EINVAL;
	}

	uint8_t *copy = malloc(from->size);
	if (copy == NULL) {
		return DNSSEC_ENOMEM;
	}

	memmove(copy, from->data, from->size);

	to->size = from->size;
	to->data = copy;

	return DNSSEC_EOK;
}

_public_
int dnssec_binary_resize(dnssec_binary_t *data, size_t new_size)
{
	if (!data) {
		return DNSSEC_EINVAL;
	}

	uint8_t *new_data = realloc(data->data, new_size);
	if (new_size > 0 && new_data == NULL) {
		return DNSSEC_ENOMEM;
	}

	data->data = new_data;
	data->size = new_size;

	return DNSSEC_EOK;
}

_public_
int dnssec_binary_cmp(const dnssec_binary_t *one, const dnssec_binary_t *two)
{
	if (one == two) {
		return 0;
	}

	uint8_t *data_one = one ? one->data : NULL;
	uint8_t *data_two = two ? two->data : NULL;

	if (data_one == data_two) {
		return 0;
	} else if (data_one == NULL) {
		return -1;
	} else if (data_two == NULL) {
		return +1;
	}

	size_t min_size = one->size <= two->size ? one->size : two->size;
	int cmp = memcmp(data_one, data_two, min_size);
	if (cmp != 0) {
		return cmp;
	} else if (one->size == two->size) {
		return 0;
	} else if (one->size < two->size) {
		return -1;
	} else {
		return +1;
	}
}

_public_
void dnssec_binary_ltrim(dnssec_binary_t *binary)
{
	if (!binary || !binary->data) {
		return;
	}

	size_t start = 0;
	while (start + 1 < binary->size && binary->data[start] == 0x00) {
		start += 1;
	}

	if (start == 0) {
		return;
	}

	size_t new_size = binary->size - start;

	memmove(binary->data, binary->data + start, new_size);
	binary->size = new_size;
}

_public_
int dnssec_binary_from_base64(const dnssec_binary_t *base64,
			      dnssec_binary_t *binary)
{
	if (!base64 || !binary) {
		return DNSSEC_EINVAL;
	}

	if (base64->size == 0) {
		clear_struct(binary);
		return DNSSEC_EOK;
	}

	size_t raw_size = BASE64_DECODE_LENGTH(base64->size);
	uint8_t *raw = malloc(raw_size);
	if (raw == NULL) {
		return DNSSEC_ENOMEM;
	}

	size_t real_size = base64_decode_raw(base64->data, base64->size,
					     raw, raw_size);
	if (real_size == 0) {
		free(raw);
		return DNSSEC_EINVAL;
	}

	binary->data = raw;
	binary->size = real_size;

	return DNSSEC_EOK;
}

_public_
int dnssec_binary_to_base64(const dnssec_binary_t *binary,
			    dnssec_binary_t *base64)
{
	if (!binary || !base64) {
		return DNSSEC_EINVAL;
	}

	size_t base64_size = BASE64_ENCODE_RAW_LENGTH(binary->size);
	int r = dnssec_binary_resize(base64, base64_size);
	if (r != DNSSEC_EOK) {
		return r;
	}

	base64_encode_raw(base64->data, binary->size, binary->data);

	return DNSSEC_EOK;
}
