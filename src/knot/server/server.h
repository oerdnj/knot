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
 * \file server.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Core server functions.
 *
 * Contains the main high-level server structure (server_t) and interface
 * to functions taking care of initialization of the server and clean-up.
 *
 * \addtogroup server
 * @{
 */

#pragma once

#include "knot/common/evsched.h"
#include "libknot/internal/lists.h"
#include "knot/common/fdset.h"
#include "libknot/internal/net.h"
#include "libknot/internal/namedb/namedb.h"
#include "knot/server/dthreads.h"
#include "knot/server/rrl.h"
#include "knot/worker/pool.h"
#include "knot/zone/zonedb.h"

/* Forwad declarations. */
struct iface;
struct server;
struct conf;

/*! \brief I/O handler structure.
  */
typedef struct iohandler {
	struct node        n;
	struct server      *server; /*!< Reference to server */
	dt_unit_t          *unit;   /*!< Threading unit */
	unsigned           *thread_state; /*!< Thread state */
	unsigned           *thread_id; /*!< Thread identifier. */
} iohandler_t;

/*! \brief Server state flags.
 */
typedef enum {
	ServerIdle    = 0 << 0, /*!< Server is idle. */
	ServerRunning = 1 << 0, /*!< Server is running. */
	ServerReload  = 1 << 1  /*!< Server reload requested. */
} server_state;

/*!
 * \brief Server interface structure.
 */
typedef struct iface {
	struct node n;
	int fd[2];
	struct sockaddr_storage addr;
} iface_t;

/* Handler types. */
#define IO_COUNT 2
enum {
	IO_UDP    = 0,
	IO_TCP    = 1
};

typedef struct ifacelist {
	ref_t ref;
	list_t l;
	list_t u;
} ifacelist_t;

/*!
 * \brief Main server structure.
 *
 * Keeps references to all important structures needed for operation.
 */
typedef struct server {

	/*! \brief Server state tracking. */
	volatile unsigned state;

	/*! \brief Zone database. */
	knot_zonedb_t *zone_db;
	namedb_t *timers_db;

	/*! \brief I/O handlers. */
	unsigned tu_size;
	iohandler_t handler[IO_COUNT];

	/*! \brief Background jobs. */
	worker_pool_t *workers;

	/*! \brief Event scheduler. */
	dt_unit_t *iosched;
	evsched_t sched;

	/*! \brief List of interfaces. */
	ifacelist_t* ifaces;

	/*! \brief Rate limiting. */
	rrl_table_t *rrl;

} server_t;

/*!
 * \brief Initializes the server structure.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int server_init(server_t *server, int bg_workers);

/*!
 * \brief Properly destroys the server structure.
 *
 * \param server Server structure to be used for operation.
 */
void server_deinit(server_t *server);

/*!
 * \brief Starts the server.
 *
 * \param server Server structure to be used for operation.
 * \param async  Don't wait for zones to load if true.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 *
 */
int server_start(server_t *server, bool async);

/*!
 * \brief Waits for the server to finish.
 *
 * \param server Server structure to be used for operation.
 *
 */
void server_wait(server_t *server);

/*!
 * \brief Reload server configuration.
 *
 * \param server Server instance.
 * \param cf Config file path.
 * \return
 */
int server_reload(server_t *server, const char *cf);

/*!
 * \brief Requests server to stop.
 *
 * \param server Server structure to be used for operation.
 */
void server_stop(server_t *server);

/*!
 * \brief Server reconfiguration routine.
 *
 * Routine for dynamic server reconfiguration.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOTRUNNING if the server is not running.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ERROR unspecified error.
 */
int server_reconfigure(conf_t *conf, void *data);

/*!
 * \brief Reconfigure zone database.
 *
 * Routine for dynamic server reconfiguration.
 *
 * \return KNOT_EOK on success or KNOT_ error
 */
int server_update_zones(conf_t *conf, void *data);

/*!
 * \brief Update fdsets from current interfaces list.
 * \param s Server.
 * \param fds Filedescriptor set.
 * \param type I/O type (UDP/TCP).
 * \return new interface list
 */
ref_t *server_set_ifaces(server_t *s, fdset_t *fds, int type);

/*! @} */
