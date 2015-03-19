/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "knot/conf/scheme.h"
#include "knot/conf/tools.h"
#include "knot/common/log.h"
#include "knot/ctl/remote.h"
#include "knot/server/rrl.h"
#include "knot/updates/acl.h"
#include "libknot/rrtype/opt.h"
#include "dnssec/lib/dnssec/tsig.h"

#include "knot/modules/synth_record.h"
#include "knot/modules/dnsproxy.h"
#ifdef HAVE_ROSEDB
#include "knot/modules/rosedb.h"
#endif
#if USE_DNSTAP
#include "knot/modules/dnstap.h"
#endif

static const lookup_table_t key_algs[] = {
	{ DNSSEC_TSIG_HMAC_MD5,    "hmac-md5" },
	{ DNSSEC_TSIG_HMAC_SHA1,   "hmac-sha1" },
	{ DNSSEC_TSIG_HMAC_SHA224, "hmac-sha224" },
	{ DNSSEC_TSIG_HMAC_SHA256, "hmac-sha256" },
	{ DNSSEC_TSIG_HMAC_SHA384, "hmac-sha384" },
	{ DNSSEC_TSIG_HMAC_SHA512, "hmac-sha512" },
	{ 0, NULL }
};

static const lookup_table_t acl_actions[] = {
	{ ACL_ACTION_DENY, "deny" },
	{ ACL_ACTION_XFER, "xfer" },
	{ ACL_ACTION_NOTF, "notify" },
	{ ACL_ACTION_DDNS, "update" },
	{ ACL_ACTION_CNTL, "control" },
	{ 0, NULL }
};

static const lookup_table_t serial_policies[] = {
	{ SERIAL_POLICY_INCREMENT, "increment" },
	{ SERIAL_POLICY_UNIXTIME,  "unixtime" },
	{ 0, NULL }
};

static const lookup_table_t log_severities[] = {
	{ LOG_UPTO(LOG_CRIT),    "critical" },
	{ LOG_UPTO(LOG_ERR),     "error" },
	{ LOG_UPTO(LOG_WARNING), "warning" },
	{ LOG_UPTO(LOG_NOTICE),  "notice" },
	{ LOG_UPTO(LOG_INFO),    "info" },
	{ LOG_UPTO(LOG_DEBUG),   "debug" },
	{ 0, NULL }
};

static const yp_item_t desc_server[] = {
	{ C_IDENT,              YP_TSTR,  YP_VNONE },
	{ C_VERSION,            YP_TSTR,  YP_VNONE },
	{ C_NSID,               YP_TDATA, YP_VDATA = { 0, NULL, hex_text_to_bin,
	                                               hex_text_to_txt } },
	{ C_RUNDIR,             YP_TSTR,  YP_VSTR = { RUN_DIR } },
	{ C_USER,               YP_TSTR,  YP_VNONE },
	{ C_PIDFILE,            YP_TSTR,  YP_VSTR = { "knot.pid" } },
	{ C_WORKERS,            YP_TINT,  YP_VINT = { 1, 255, YP_NIL } },
	{ C_BG_WORKERS,         YP_TINT,  YP_VINT = { 1, 255, YP_NIL } },
	{ C_ASYNC_START,        YP_TBOOL, YP_VNONE },
	{ C_MAX_CONN_IDLE,      YP_TINT,  YP_VINT = { 0, INT32_MAX, 20, YP_STIME } },
	{ C_MAX_CONN_HANDSHAKE, YP_TINT,  YP_VINT = { 0, INT32_MAX, 5, YP_STIME } },
	{ C_MAX_CONN_REPLY,     YP_TINT,  YP_VINT = { 0, INT32_MAX, 10, YP_STIME } },
	{ C_MAX_TCP_CLIENTS,    YP_TINT,  YP_VINT = { 0, INT32_MAX, 100 } },
	{ C_MAX_UDP_PAYLOAD,    YP_TINT,  YP_VINT = { KNOT_EDNS_MIN_UDP_PAYLOAD,
	                                              KNOT_EDNS_MAX_UDP_PAYLOAD,
	                                              4096, YP_SSIZE } },
	{ C_TRANSFERS,          YP_TINT,  YP_VINT = { 1, INT32_MAX, 10 } },
	{ C_RATE_LIMIT,         YP_TINT,  YP_VINT = { 0, INT32_MAX, 0 } },
	{ C_RATE_LIMIT_SLIP,    YP_TINT,  YP_VINT = { 1, RRL_SLIP_MAX, 1 } },
	{ C_RATE_LIMIT_SIZE,    YP_TINT,  YP_VINT = { 1, INT32_MAX, 393241 } },
	{ C_LISTEN,             YP_TADDR, YP_VADDR = { 53 }, YP_FMULTI },
	{ C_COMMENT,            YP_TSTR,  YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_key[] = {
	{ C_ID,      YP_TDNAME, YP_VNONE },
	{ C_ALG,     YP_TOPT,   YP_VOPT = { key_algs, DNSSEC_TSIG_UNKNOWN } },
	{ C_SECRET,  YP_TB64,   YP_VNONE },
	{ C_COMMENT, YP_TSTR,   YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_acl[] = {
	{ C_ID,      YP_TSTR, YP_VNONE },
	{ C_ADDR,    YP_TNET, YP_VNONE },
	{ C_KEY,     YP_TREF, YP_VREF = { C_KEY }, YP_FNONE, { check_ref } },
	{ C_ACTION,  YP_TOPT, YP_VOPT = { acl_actions, ACL_ACTION_DENY }, YP_FMULTI },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_control[] = {
	{ C_LISTEN,  YP_TADDR, YP_VADDR = { REMOTE_PORT, REMOTE_SOCKET } },
	{ C_ACL,     YP_TREF,  YP_VREF = { C_ACL }, YP_FMULTI, { check_ref } },
	{ C_COMMENT, YP_TSTR,  YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_remote[] = {
	{ C_ID,      YP_TSTR,  YP_VNONE },
	{ C_ADDR,    YP_TADDR, YP_VADDR = { 53 } },
	{ C_VIA,     YP_TADDR, YP_VNONE },
	{ C_KEY,     YP_TREF,  YP_VREF = { C_KEY }, YP_FNONE, { check_ref } },
	{ C_COMMENT, YP_TSTR,  YP_VNONE },
	{ NULL }
};

#define ZONE_ITEMS \
	{ C_STORAGE,        YP_TSTR,  YP_VSTR = { STORAGE_DIR } }, \
	{ C_MASTER,         YP_TREF,  YP_VREF = { C_RMT }, YP_FMULTI, { check_ref } }, \
	{ C_NOTIFY,         YP_TREF,  YP_VREF = { C_RMT }, YP_FMULTI, { check_ref } }, \
	{ C_ACL,            YP_TREF,  YP_VREF = { C_ACL }, YP_FMULTI, { check_ref } }, \
	{ C_SEM_CHECKS,     YP_TBOOL, YP_VNONE }, \
	{ C_DISABLE_ANY,    YP_TBOOL, YP_VNONE }, \
	{ C_NOTIFY_TIMEOUT, YP_TINT,  YP_VINT = { 1, INT32_MAX, 60, YP_STIME } }, \
	{ C_NOTIFY_RETRIES, YP_TINT,  YP_VINT = { 1, INT32_MAX, 5 } }, \
	{ C_ZONEFILE_SYNC,  YP_TINT,  YP_VINT = { 0, INT32_MAX, 0, YP_STIME } }, \
	{ C_IXFR_DIFF,      YP_TBOOL, YP_VNONE }, \
	{ C_IXFR_FSLIMIT,   YP_TINT,  YP_VINT = { 0, INT64_MAX, INT64_MAX, YP_SSIZE } }, \
	{ C_DNSSEC_ENABLE,  YP_TBOOL, YP_VNONE }, \
	{ C_DNSSEC_KEYDIR,  YP_TSTR,  YP_VSTR = { "keys" } }, \
	{ C_SIG_LIFETIME,   YP_TINT,  YP_VINT = { 3 * 3600, INT32_MAX, 30 * 24 * 3600, YP_STIME } }, \
	{ C_SERIAL_POLICY,  YP_TOPT,  YP_VOPT = { serial_policies, SERIAL_POLICY_INCREMENT } }, \
	{ C_MODULE,         YP_TDATA, YP_VDATA = { 0, NULL, mod_id_to_bin, mod_id_to_txt }, \
	                              YP_FMULTI, { check_modref } }, \
	{ C_COMMENT,        YP_TSTR,  YP_VNONE },

static const yp_item_t desc_template[] = {
	{ C_ID, YP_TSTR, YP_VNONE },
	ZONE_ITEMS
	{ NULL }
};

static const yp_item_t desc_zone[] = {
	{ C_DOMAIN, YP_TDNAME, YP_VNONE },
	{ C_FILE,   YP_TSTR,   YP_VNONE },
	{ C_TPL,    YP_TREF,   YP_VREF = { C_TPL }, YP_FNONE, { check_ref } },
	ZONE_ITEMS
	{ NULL }
};

static const yp_item_t desc_log[] = {
	{ C_TO,      YP_TSTR, YP_VNONE },
	{ C_SERVER,  YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_ZONE,    YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_ANY,     YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

const yp_item_t conf_scheme[] = {
	{ C_SRV,  YP_TGRP, YP_VGRP = { desc_server } },
	{ C_KEY,  YP_TGRP, YP_VGRP = { desc_key }, YP_FMULTI },
	{ C_ACL,  YP_TGRP, YP_VGRP = { desc_acl }, YP_FMULTI },
	{ C_CTL,  YP_TGRP, YP_VGRP = { desc_control } },
	{ C_RMT,  YP_TGRP, YP_VGRP = { desc_remote }, YP_FMULTI },
/* MODULES */
	{ C_MOD_SYNTH_RECORD, YP_TGRP, YP_VGRP = { scheme_mod_synth_record }, YP_FMULTI },
	{ C_MOD_DNSPROXY,     YP_TGRP, YP_VGRP = { scheme_mod_dnsproxy }, YP_FMULTI },
#if HAVE_ROSEDB
	{ C_MOD_ROSEDB,       YP_TGRP, YP_VGRP = { scheme_mod_rosedb }, YP_FMULTI },
#endif
#if USE_DNSTAP
	{ C_MOD_DNSTAP,       YP_TGRP, YP_VGRP = { scheme_mod_dnstap }, YP_FMULTI },
#endif
/***********/
	{ C_TPL,  YP_TGRP, YP_VGRP = { desc_template }, YP_FMULTI },
	{ C_ZONE, YP_TGRP, YP_VGRP = { desc_zone }, YP_FMULTI },
	{ C_LOG,  YP_TGRP, YP_VGRP = { desc_log }, YP_FMULTI },
	{ C_INCL, YP_TSTR, YP_VNONE, YP_FNONE, { NULL, include_file } },
	{ NULL }
};
