/*!
 * \file tcp-handler.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief TCP sockets threading model.
 *
 * The master socket distributes incoming connections among
 * the worker threads ("buckets"). Each threads processes it's own
 * set of sockets, and eliminates mutual exclusion problem by doing so.
 *
 * \addtogroup server
 * @{
 */

#ifndef _CUTEDNS_TCPHANDLER_H_
#define _CUTEDNS_TCPHANDLER_H_

#include "server/socket.h"
#include "server/server.h"
#include "server/dthreads.h"


/*!
 * \brief TCP master socket runnable.
 *
 * Accepts new TCP connections and distributes them among the rest
 * of the threads in unit, which are repurposed as a TCP connection pools.
 * New pools are initialized ad-hoc, function implements a cancellation point.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int tcp_master(dthread_t *thread);

#endif // _CUTEDNS_TCPHANDLER_H_

/*! @} */

