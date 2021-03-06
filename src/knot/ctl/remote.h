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
 * \file remote.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Functions for remote control interface.
 *
 * \addtogroup ctl
 * @{
 */

#pragma once

#include "knot/conf/conf.h"
#include "libknot/packet/pkt.h"
#include "libknot/rrset.h"
#include "libknot/dnssec/key.h"
#include "knot/server/server.h"

/*! \brief Default remote control tool port. */
#define REMOTE_DPORT 5533

/*!
 * \brief Bind RC interface according to configuration.
 *
 * \param desc Interface descriptor (address, port).
 *
 * \retval socket if passed.
 * \retval knot_error else.
 */
int remote_bind(conf_iface_t *desc);

/*!
 * \brief Unbind from RC interface and close socket.
 *
 * \note Breaks all pending connections.
 *
 * \param desc Interface descriptor (address, port).
 * \param socket Interface socket
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_unbind(conf_iface_t *desc, int sock);

/*!
 * \brief Poll new events on RC socket.
 *
 * \param sock     RC interface socket.
 * \param sigmask  Signal mask to use during blocking waiting.
 *
 * \return number of polled events or -1 on error.
 */
int remote_poll(int sock, const sigset_t *sigmask);

/*!
 * \brief Start a RC connection with remote.
 *
 * \param r RC interface socket.
 * \param a Destination for remote party address (or NULL if not interested).
 * \param buf Buffer for RC command.
 * \param buflen Maximum buffer size.
 *
 * \return client TCP socket if success.
 * \return KNOT_ECONNREFUSED if fails to receive command.
 */
int remote_recv(int sock, struct sockaddr_storage *addr, uint8_t *buf,
                size_t *buflen);

/*!
 * \brief Parse a RC command.
 *
 * \param pkt Query packet.
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_parse(knot_pkt_t* pkt);

/*!
 * \brief Execute command and prepare answer for client.
 *
 * \param fd Remote client
 * \param s Server instance.
 * \param pkt Parsed RC command.
 * \param rwire Buffer for response.
 * \param rlen Maximum buffer size for response.
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_answer(int sock, server_t *s, knot_pkt_t *pkt);

/*!
 * \brief Accept new client, receive command, process it and send response.
 *
 * \note This should be used as a high-level API for workers.
 *
 * \param s Server instance.
 * \param ctl_if Control interface.
 * \param sock RC interface socket.
 * \param buf Buffer for commands/responses.
 * \param buflen Maximum buffer size.
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_process(server_t *s, conf_iface_t *ctl_if, int sock,
                   uint8_t* buf, size_t buflen);

/* Functions for creating RC packets. */

/*!
 * \brief Build a RC command packet, TSIG key is optional.
 *
 * \note This doesn't sign packet, see remote_query_sign().
 *
 * \param query Command name, f.e. 'reload'.
 * \param key TSIG key for space reservation (or NULL).
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
knot_pkt_t* remote_query(const char *query, const knot_tsig_key_t *key);

/*!
 * \brief Sign a RC command packet using TSIG key.
 *
 * \param wire RC packet in wire format.
 * \param size RC packet size.
 * \param maxlen Maximum buffer size.
 * \param key TSIG key.
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_query_sign(uint8_t *wire, size_t *size, size_t maxlen,
                      const knot_tsig_key_t *key);

/*! \todo #1291 RR building should be a part of DNS library. */

/*!
 * \brief Create a RR of a given name and type.
 *
 * \param k RR set name.
 * \param t RR set type.
 *
 * \return created RR set or NULL.
 */
int remote_build_rr(knot_rrset_t *rr, const char *k, uint16_t t);

/*!
 * \brief Create a TXT rdata.
 * \param v Text as a string.
 * \param v_len Text length.
 * \return Created rdata or NULL.
 */
int remote_create_txt(knot_rrset_t *rr, const char *v, size_t v_len);

/*!
 * \brief Create a CNAME rdata.
 * \param d Domain name as a string.
 * \return Created rdata or NULL.
 */
int remote_create_ns(knot_rrset_t *rr, const char *d);

/*!
 * \brief Print TXT rdata to stdout.
 * \param rd TXT rdata.
 * \return KNOT_EOK
 */
int remote_print_txt(const knot_rrset_t *rrset, uint16_t i);

/*! @} */
