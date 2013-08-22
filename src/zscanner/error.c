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

#include <config.h>
#include <stdlib.h>	// NULL

#include "zscanner/error.h"

typedef struct {
	int        code;
	const char *text;
	const char *code_name;
} err_table_t;

#define ERR_ITEM(code, text) { code, text, #code }

const err_table_t err_msgs[] = {
	ERR_ITEM( ZSCANNER_OK, "OK" ),

	/* Zone file loader errors. */
	ERR_ITEM( FLOADER_EFSTAT,
	          "Fstat error." ),
	ERR_ITEM( FLOADER_EDIRECTORY,
	          "Zone file is a directory." ),
	ERR_ITEM( FLOADER_EEMPTY,
	          "Empty zone file." ),
	ERR_ITEM( FLOADER_EMMAP,
	          "Mmap error." ),
	ERR_ITEM( FLOADER_EMUNMAP,
	          "Munmap error." ),
	ERR_ITEM( FLOADER_ESCANNER,
	          "Zone processing error." ),

	/* Zone scanner errors. */
	ERR_ITEM( ZSCANNER_UNCOVERED_STATE,
	          "General scanner error." ),
	ERR_ITEM( ZSCANNER_UNCLOSED_MULTILINE,
	          "Unclosed last multiline block." ),
	ERR_ITEM( ZSCANNER_ELEFT_PARENTHESIS,
	          "Too many left parentheses." ),
	ERR_ITEM( ZSCANNER_ERIGHT_PARENTHESIS,
	          "Too many right parentheses." ),
	ERR_ITEM( ZSCANNER_EUNSUPPORTED_TYPE,
	          "Unsupported record type." ),
	ERR_ITEM( ZSCANNER_EBAD_PREVIOUS_OWNER,
	          "Previous owner is invalid." ),
	ERR_ITEM( ZSCANNER_EBAD_DNAME_CHAR,
	          "Bad domain name character." ),
	ERR_ITEM( ZSCANNER_EBAD_OWNER,
	          "Owner is invalid." ),
	ERR_ITEM( ZSCANNER_ELABEL_OVERFLOW,
	          "Maximal domain name label length has exceeded." ),
	ERR_ITEM( ZSCANNER_EDNAME_OVERFLOW,
	          "Maximal domain name length has exceeded." ),
	ERR_ITEM( ZSCANNER_EBAD_NUMBER,
	          "Bad number." ),
	ERR_ITEM( ZSCANNER_ENUMBER64_OVERFLOW,
	          "Number is too big." ),
	ERR_ITEM( ZSCANNER_ENUMBER32_OVERFLOW,
	          "Number is bigger than 32 bits." ),
	ERR_ITEM( ZSCANNER_ENUMBER16_OVERFLOW,
	          "Number is bigger than 16 bits." ),
	ERR_ITEM( ZSCANNER_ENUMBER8_OVERFLOW,
	          "Number is bigger than 8 bits." ),
	ERR_ITEM( ZSCANNER_EFLOAT_OVERFLOW,
	          "Float number overflow." ),
	ERR_ITEM( ZSCANNER_ERDATA_OVERFLOW,
	          "Maximal record data length has exceeded." ),
	ERR_ITEM( ZSCANNER_EITEM_OVERFLOW,
	          "Maximal item length has exceeded." ),
	ERR_ITEM( ZSCANNER_EBAD_ADDRESS_CHAR,
	          "Bad address character." ),
	ERR_ITEM( ZSCANNER_EBAD_IPV4,
	          "Bad IPv4 address." ),
	ERR_ITEM( ZSCANNER_EBAD_IPV6,
	          "Bad IPv6 address." ),
	ERR_ITEM( ZSCANNER_EBAD_GATEWAY,
	          "Bad gateway." ),
	ERR_ITEM( ZSCANNER_EBAD_GATEWAY_KEY,
	          "Bad gateway key." ),
	ERR_ITEM( ZSCANNER_EBAD_APL,
	          "Bad address prefix list." ),
	ERR_ITEM( ZSCANNER_EBAD_RDATA,
	          "Bad record data." ),
	ERR_ITEM( ZSCANNER_EBAD_HEX_RDATA,
	          "Bad record data in hex format." ),
	ERR_ITEM( ZSCANNER_EBAD_HEX_CHAR,
	          "Bad hexadecimal character." ),
	ERR_ITEM( ZSCANNER_EBAD_BASE64_CHAR,
	          "Bad Base64 character." ),
	ERR_ITEM( ZSCANNER_EBAD_BASE32HEX_CHAR,
	          "Bad Base32hex character." ),
	ERR_ITEM( ZSCANNER_EBAD_REST,
	          "Unexpected data." ),
	ERR_ITEM( ZSCANNER_EBAD_TIMESTAMP_CHAR,
	          "Bad timestamp character." ),
	ERR_ITEM( ZSCANNER_EBAD_TIMESTAMP_LENGTH,
	          "Bad timestamp length." ),
	ERR_ITEM( ZSCANNER_EBAD_TIMESTAMP,
	          "Bad timestamp." ),
	ERR_ITEM( ZSCANNER_EBAD_DATE,
	          "Bad date." ),
	ERR_ITEM( ZSCANNER_EBAD_TIME,
	          "Bad time." ),
	ERR_ITEM( ZSCANNER_EBAD_TIME_UNIT,
	          "Bad time unit." ),
	ERR_ITEM( ZSCANNER_EBAD_BITMAP,
	          "Bad bitmap." ),
	ERR_ITEM( ZSCANNER_ETEXT_OVERFLOW,
	          "Text is too long." ),
	ERR_ITEM( ZSCANNER_EBAD_TEXT_CHAR,
	          "Bad text character." ),
	ERR_ITEM( ZSCANNER_EBAD_TEXT,
	          "Bad text string." ),
	ERR_ITEM( ZSCANNER_EBAD_DIRECTIVE,
	          "Bad directive." ),
	ERR_ITEM( ZSCANNER_EBAD_TTL,
	          "Bad zone TTL." ),
	ERR_ITEM( ZSCANNER_EBAD_ORIGIN,
	          "Bad zone origin." ),
	ERR_ITEM( ZSCANNER_EBAD_INCLUDE_FILENAME,
	          "Bad filename in include directive." ),
	ERR_ITEM( ZSCANNER_EBAD_INCLUDE_ORIGIN,
	          "Bad origin in include directive." ),
	ERR_ITEM( ZSCANNER_EUNPROCESSED_INCLUDE,
	          "Include file processing error." ),
	ERR_ITEM( ZSCANNER_EUNOPENED_INCLUDE,
	          "Include file opening error." ),
	ERR_ITEM( ZSCANNER_EBAD_RDATA_LENGTH,
	          "The rdata length statement is incorrect." ),
	ERR_ITEM( ZSCANNER_ECANNOT_TEXT_DATA,
	          "Unable to process text form for this type." ),
	ERR_ITEM( ZSCANNER_EBAD_LOC_DATA,
	          "Bad zone location data." ),
	ERR_ITEM( ZSCANNER_EUNKNOWN_BLOCK,
	          "Unknown rdata block." ),
	ERR_ITEM( ZSCANNER_EBAD_ALGORITHM,
	          "Bad algorithm." ),
	ERR_ITEM( ZSCANNER_EBAD_CERT_TYPE,
	          "Bad certificate type." ),
	ERR_ITEM( ZSCANNER_EBAD_EUI_LENGTH,
	          "Bad EUI length." ),
	ERR_ITEM( ZSCANNER_EBAD_L64_LENGTH,
	          "Bad 64-bit locator." ),
	ERR_ITEM( ZSCANNER_EBAD_CHAR_COLON,
	          "Missing colon character." ),
	ERR_ITEM( ZSCANNER_EBAD_CHAR_DASH,
	          "Missing dash character." ),

	ERR_ITEM( 0, NULL ) // Terminator
};

const char* zscanner_strerror(const int code)
{
	const err_table_t *err = err_msgs;

	while (err->text != NULL) {
		if (err->code == code) {
			return err->text;
		}
		err++;
	}

	return NULL;
}

const char* zscanner_errorname(const int code)
{
	const err_table_t *err = err_msgs;

	while (err->text != NULL) {
		if (err->code == code) {
			return err->code_name;
		}
		err++;
	}

	return NULL;
}