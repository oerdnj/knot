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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <grp.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <pwd.h>
#include <urcu.h>

#include "knot/ctl/process.h"
#include "knot/conf/conf.h"
#include "knot/common/log.h"
#include "libknot/errcode.h"
#include "libknot/internal/mem.h"
#include "libknot/libknot.h"

#define LOCK_FILE	"knot.lock"

char* pid_filename()
{
	rcu_read_lock();
	conf_val_t val = conf_get(conf(), C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&val, NULL);
	val = conf_get(conf(), C_SRV, C_PIDFILE);
	char *pidfile = conf_abs_path(&val, rundir);
	rcu_read_unlock();

	if (rundir != NULL) {
		free(rundir);
		return pidfile;
	} else {
		return NULL;
	}
}

pid_t pid_read(const char* fn)
{
	char buf[64];

	if (fn) {
		FILE *fp = fopen(fn, "r");
		if (!fp) {
			return KNOT_ENOENT;
		}

		int readb = 0;
		int rc = fread(buf, 1, 1, fp);
		while (rc > 0) {
			if (++readb == sizeof(buf) - 1) {
				break;
			}
			rc = fread(buf + readb, 1, 1, fp);
		}
		buf[readb] = '\0';
		fclose(fp);

		// Check read result
		if (readb < 1) {
			return KNOT_ENOENT;
		}

		// Convert pid
		char* ep = 0;
		unsigned long pid = strtoul(buf, &ep, 10);
		if ((errno == ERANGE) ||
		    (*ep && !isspace((unsigned char)(*ep)))) {
			return KNOT_ERANGE;
		}

		return (pid_t)pid;
	}

	return KNOT_EINVAL;
}

int pid_write(const char* fn)
{
	if (!fn)
		return KNOT_EINVAL;

	/* Convert. */
	char buf[64];
	int len = 0;
	len = snprintf(buf, sizeof(buf), "%lu", (unsigned long) getpid());
	if (len < 0)
		return KNOT_EINVAL;

	/* Create file. */
	int ret = KNOT_EOK;
	int fd = open(fn, O_RDWR|O_CREAT, 0644);
	if (fd >= 0) {
		if (write(fd, buf, len) != len)
			ret = KNOT_ERROR;
		close(fd);
	} else {
		ret = knot_map_errno(errno);
	}

	return ret;
}

int pid_remove(const char* fn)
{
	if (unlink(fn) < 0) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int pid_running(pid_t pid)
{
	return kill(pid, 0) == 0;
}

int proc_update_privileges(int uid, int gid)
{
#ifdef HAVE_SETGROUPS
	/* Drop supplementary groups. */
	if ((uid_t)uid != getuid() || (gid_t)gid != getgid()) {
		if (setgroups(0, NULL) < 0) {
			log_warning("failed to drop supplementary groups for "
			            "UID '%d' (%s)", getuid(), strerror(errno));
		}
# ifdef HAVE_INITGROUPS
		struct passwd *pw;
		if ((pw = getpwuid(uid)) == NULL) {
			log_warning("failed to get passwd entry for UID '%d' (%s)",
				    uid, strerror(errno));
		} else {
			if (initgroups(pw->pw_name, gid) < 0) {
				log_warning("failed to set supplementary groups "
				            "for UID '%d' (%s)", uid, strerror(errno));
			}
		}
# endif /* HAVE_INITGROUPS */
	}
#endif /* HAVE_SETGROUPS */

	/* Watch uid/gid. */
	if ((gid_t)gid != getgid()) {
		log_info("changing GID to '%d'", gid);
		if (setregid(gid, gid) < 0) {
			log_error("failed to change GID to '%d'", gid);
		}
	}
	if ((uid_t)uid != getuid()) {
		log_info("changing UID to '%d'", uid);
		if (setreuid(uid, uid) < 0) {
			log_error("failed to change UID to '%d'", uid);
		}
	}

	/* Check storage writability. */
	conf_iter_t iter = conf_iter(conf(), C_ZONE);
	while (iter.code == KNOT_EOK) {
		conf_val_t id = conf_iter_id(conf(), &iter);
		conf_val_t val = conf_zone_get(conf(), C_STORAGE, conf_dname(&id));
		char *storage = conf_abs_path(&val, NULL);
		if (storage == NULL) {
			conf_iter_finish(conf(), &iter);
			return KNOT_ENOMEM;
		}

		char *lfile = sprintf_alloc("%s/%s", storage, LOCK_FILE);
		assert(lfile != NULL);
		FILE *fp = fopen(lfile, "w");
		if (fp == NULL) {
			log_error("storage directory '%s' is not writable",
			          storage);
			free(lfile);
			free(storage);
			conf_iter_finish(conf(), &iter);
			return KNOT_EACCES;
		} else {
			fclose(fp);
			unlink(lfile);
		}
		free(lfile);
		free(storage);

		conf_iter_next(conf(), &iter);
	}
	conf_iter_finish(conf(), &iter);

	return KNOT_EOK;
}

char *pid_check_and_create()
{
	struct stat st;
	char* pidfile = pid_filename();
	pid_t pid = pid_read(pidfile);

	/* Check PID for existence and liveness. */
	if (pid > 0 && pid_running(pid)) {
		log_error("server PID found, already running");
		free(pidfile);
		return NULL;
	} else if (stat(pidfile, &st) == 0) {
		log_warning("removing stale PID file '%s'", pidfile);
		pid_remove(pidfile);
	}

	/* Create a PID file. */
	int ret = pid_write(pidfile);
	if (ret != KNOT_EOK) {
		log_error("failed to create a PID file '%s'", pidfile);
		free(pidfile);
		return NULL;
	}

	return pidfile;
}
