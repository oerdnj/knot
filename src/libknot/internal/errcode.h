/*!
* \file errcode.h
*
* \author Lubos Slovak <lubos.slovak@nic.cz>
* \author Marek Vavrusa <marek.vavrusa@nic.cz>
*
* \brief Error codes and function for getting error message.
*
* \addtogroup common_lib
* @{
*/
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

#pragma once

#include <errno.h>

/*! \brief Error codes used in the library. */
enum knot_error {
	KNOT_EOK = 0,

	/* Directly mapped error codes. */
	KNOT_ENOMEM        = -ENOMEM,
	KNOT_EINVAL        = -EINVAL,
	KNOT_ENOTSUP       = -ENOTSUP,
	KNOT_EBUSY         = -EBUSY,
	KNOT_EAGAIN        = -EAGAIN,
	KNOT_EACCES        = -EACCES,
	KNOT_ECONNREFUSED  = -ECONNREFUSED,
	KNOT_EISCONN       = -EISCONN,
	KNOT_EADDRINUSE    = -EADDRINUSE,
	KNOT_ENOENT        = -ENOENT,
	KNOT_EEXIST        = -EEXIST,
	KNOT_ERANGE        = -ERANGE,
	KNOT_EADDRNOTAVAIL = -EADDRNOTAVAIL,

	KNOT_ERROR_MIN = -1000,

	/* General errors. */
	KNOT_ERROR = KNOT_ERROR_MIN,
	KNOT_ENOTRUNNING,
	KNOT_EPARSEFAIL,
	KNOT_ESEMCHECK,
	KNOT_EEXPIRED,
	KNOT_EUPTODATE,
	KNOT_EFEWDATA,
	KNOT_ESPACE,
	KNOT_EMALF,
	KNOT_ECRYPTO,
	KNOT_ENSEC3PAR,
	KNOT_ENSEC3CHAIN,
	KNOT_EOUTOFZONE,
	KNOT_EHASH,
	KNOT_EZONEINVAL,
	KNOT_EZONENOENT,
	KNOT_ENOZONE,
	KNOT_ENONODE,
	KNOT_EDNAMEPTR,
	KNOT_EPAYLOAD,
	KNOT_EPREREQ,
	KNOT_ETTL,
	KNOT_ENOXFR,
	KNOT_ENOIXFR,
	KNOT_EXFRREFUSED,
	KNOT_EDENIED,
	KNOT_ECONN,
	KNOT_ETIMEOUT,
	KNOT_EIXFRSPACE,
	KNOT_ECNAME,
	KNOT_ENODIFF,
	KNOT_EDSDIGESTLEN,
	KNOT_ENOTSIG,
	KNOT_ELIMIT,
	KNOT_EWRITABLE,
	KNOT_EOF,
	KNOT_ESYSTEM,
	KNOT_EFILE,

	/* Control states. */
	KNOT_CTL_STOP,
	KNOT_CTL_ACCEPTED,
	KNOT_CTL_ARG_REQ,

	/* Network errors. */
	KNOT_NET_EADDR,
	KNOT_NET_ESOCKET,
	KNOT_NET_ECONNECT,
	KNOT_NET_ESEND,
	KNOT_NET_ERECV,
	KNOT_NET_ETIMEOUT,

	/* Encoding errors. */
	KNOT_BASE64_ESIZE,
	KNOT_BASE64_ECHAR,
	KNOT_BASE32HEX_ESIZE,
	KNOT_BASE32HEX_ECHAR,

	/* TSIG errors. */
	KNOT_TSIG_EBADSIG,
	KNOT_TSIG_EBADKEY,
	KNOT_TSIG_EBADTIME,

	/* Key parsing errors. */
	KNOT_KEY_EPUBLIC_KEY_OPEN,
	KNOT_KEY_EPRIVATE_KEY_OPEN,
	KNOT_KEY_EPUBLIC_KEY_INVALID,

	/* DNSSEC errors. */
	KNOT_DNSSEC_EMISSINGKEYTYPE,
	KNOT_DNSSEC_ENOKEY,

	/* Yparser errors. */
	KNOT_YP_EINVAL_ITEM,
	KNOT_YP_EINVAL_DATA,
	KNOT_YP_ENOTSUP_DATA,
	KNOT_YP_ENOTSUP_ID,
	KNOT_YP_ENODATA,
	KNOT_YP_ENOID,

	/* Configuration errors. */
	KNOT_CONF_EMPTY,
	KNOT_CONF_EVERSION,
	KNOT_CONF_EREDEFINE,

	/* Processing error. */
	KNOT_LAYER_ERROR,

	KNOT_ERROR_MAX = -501
};

/*!
 * \brief Get a POSIX errno mapped to Knot error code.
 *
 * \internal
 *
 * \param fallback  Falback error code.
 * \param arg0...   Error codes allowed for lookup, list must be terminated by 0.
 *
 * \return Mapped errno or fallback error code.
 */
int knot_map_errno_internal(int fallback, int arg0, ...);

/*! @} */
