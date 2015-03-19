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
/*!
 * \file
 *
 * Access control list.
 *
 * \addtogroup server
 * @{
 */

#pragma once

#include "libknot/internal/lists.h"
#include "libknot/internal/sockaddr.h"
#include "libknot/internal/mempattern.h"
#include "libknot/rrtype/tsig.h"
#include "knot/conf/conf.h"

/*! \brief ACL actions. */
typedef enum {
	ACL_ACTION_DENY = 0,
	ACL_ACTION_XFER = 1,
	ACL_ACTION_NOTF = 2,
	ACL_ACTION_DDNS = 3,
	ACL_ACTION_CNTL = 4
} acl_action_t;

/*!
 * \brief Checks if two netblocks match.
 *
 * \param ss1     First address storage.
 * \param ss2     Second address storage.
 * \param prefix  Netblock length.
 */
bool netblock_match(const struct sockaddr_storage *ss1,
                    const struct sockaddr_storage *ss2,
                    unsigned prefix);

/*!
 * \brief Checks if the address and/or tsig key matches given ACL list.
 *
 * If a proper ACL rule is found and tsig.name is not empty,
 * tsig.secret is filled.
 *
 * \param acl      Pointer to ACL config multivalued identifier.
 * \param action   ACL action.
 * \param addr     IP address.
 * \param tsig     TSIG parameters.
 *
 * \retval true  if authenticated.
 * \retval false if not authenticated.
 */
bool acl_allowed(conf_val_t *acl, acl_action_t action,
                 const struct sockaddr_storage *addr,
                 knot_tsig_key_t *tsig);

/*! @} */
