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
%{

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "knot/conf/scheme.h"
#include "knot/conf/extra.h"
#include "knot/conf/cf-parse.h"

#define DEFAULT_PORT		53
#define DEFAULT_CTL_PORT	5533

static char *_addr = NULL;
static int _port = -1;
static char *_str = NULL;

#define ERROR_BUFFER_SIZE       512
extern int cf_lex (YYSTYPE *lvalp, void *scanner);
extern int cf_get_lineno(void *scanner);
extern char *cf_get_text(void *scanner);
extern conf_extra_t *cf_get_extra(void *scanner);
volatile int parser_ret = 0;

static void cf_print_error(void *scanner, const char *prefix, const char *msg)
{
	conf_extra_t *extra = NULL;
	int lineno = -1;
	char *filename = "";
	conf_include_t *inc = NULL;

	if (scanner) {
		extra = cf_get_extra(scanner);
		lineno = cf_get_lineno(scanner);
		inc = conf_includes_top(extra->includes);
		//extra->error = true;
	}

	if (inc && inc->filename) {
		filename = inc->filename;
	}

	printf("%s: %s (file '%s', line %d)\n",
		prefix, msg, filename, lineno);
	fflush(stdout);
}


void cf_error(void *scanner, const char *format, ...)
{
	char buffer[ERROR_BUFFER_SIZE];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	cf_print_error(scanner, "Error", buffer);
	parser_ret = -1;
}

void cf_warning(void *scanner, const char *format, ...)
{
	char buffer[ERROR_BUFFER_SIZE];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	cf_print_error(scanner, "Warning", buffer);
}

static void f_section(void *scanner, int run, const char *name)
{
	conf_extra_t *extra = cf_get_extra(scanner);
	if (extra->run != run) return;

	fprintf(extra->out, "\n%s:\n", name + 1);
}

static void f_name(void *scanner, int run, const char *name, bool is_id)
{
	conf_extra_t *extra = cf_get_extra(scanner);
	if (extra->run != run) return;

	fprintf(extra->out, "%s%s: ", is_id ? "  - " : "    ", name + 1);
}

static void f_val(void *scanner, int run, bool quote, const char *format, ...)
{
	conf_extra_t *extra = cf_get_extra(scanner);
	if (extra->run != run) return;

	if (quote) {
		fprintf(extra->out, "\"");
	}

	va_list ap;
	va_start(ap, format);
	vfprintf(extra->out, format, ap);
	va_end(ap);

	if (quote) {
		fprintf(extra->out, "\"");
	}
}

static void f_quote(void *scanner, int run, const char *name, const char *val)
{
	f_name(scanner, run, name, false);
	f_val(scanner, run, true, "%s", val);
	f_val(scanner, run, false, "\n");
}

static void f_str(void *scanner, int run, const char *name, const char *val)
{
	f_name(scanner, run, name, false);
	f_val(scanner, run, false, "%s\n", val);
}

static void f_auto_str(void *scanner, int run, const char *name, int val)
{
	if (val == 0) {
		f_name(scanner, run, name, false);
		f_val(scanner, run, true, "");
		f_val(scanner, run, false, "\n");
	}
}

static void f_bool(void *scanner, int run, const char *name, long val)
{
	f_name(scanner, run, name, false);
	f_val(scanner, run, false, "%s\n", val == 1 ? "on" : "off");
}

static void f_int(void *scanner, int run, const char *name, int val)
{
	f_name(scanner, run, name, false);
	f_val(scanner, run, false, "%i\n", val);
}

static void f_id(void *scanner, int run, const char *name, const char *val)
{
	f_name(scanner, run, name, true);
	f_val(scanner, run, false, "%s\n", val);
}

%}

%pure-parser
%parse-param{void *scanner}
%lex-param{void *scanner}
%name-prefix = "cf_"

%union {
	struct {
		char *t;
		long i;
		size_t l;
	} tok;
}

%token END INVALID_TOKEN
%token <tok> TEXT
%token <tok> NUM
%token <tok> INTERVAL
%token <tok> SIZE
%token <tok> BOOL

%token <tok> SYSTEM IDENTITY HOSTNAME SVERSION NSID KEY KEYS
%token <tok> MAX_UDP_PAYLOAD
%token <tok> TSIG_ALGO_NAME
%token <tok> WORKERS
%token <tok> BACKGROUND_WORKERS
%token <tok> ASYNC_START
%token <tok> USER
%token <tok> RUNDIR
%token <tok> PIDFILE

%token <tok> REMOTES
%token <tok> GROUPS

%token <tok> ZONES FILENAME
%token <tok> DISABLE_ANY
%token <tok> SEMANTIC_CHECKS
%token <tok> NOTIFY_RETRIES
%token <tok> NOTIFY_TIMEOUT
%token <tok> DBSYNC_TIMEOUT
%token <tok> IXFR_FSLIMIT
%token <tok> XFR_IN
%token <tok> XFR_OUT
%token <tok> UPDATE_IN
%token <tok> NOTIFY_IN
%token <tok> NOTIFY_OUT
%token <tok> BUILD_DIFFS
%token <tok> MAX_CONN_IDLE
%token <tok> MAX_CONN_HS
%token <tok> MAX_CONN_REPLY
%token <tok> MAX_TCP_CLIENTS
%token <tok> RATE_LIMIT
%token <tok> RATE_LIMIT_SIZE
%token <tok> RATE_LIMIT_SLIP
%token <tok> TRANSFERS
%token <TOK> STORAGE
%token <tok> DNSSEC_ENABLE
%token <tok> DNSSEC_KEYDIR
%token <tok> SIGNATURE_LIFETIME
%token <tok> SERIAL_POLICY
%token <tok> SERIAL_POLICY_VAL
%token <tok> QUERY_MODULE

%token <tok> INTERFACES ADDRESS PORT
%token <tok> IPA
%token <tok> IPA6
%token <tok> VIA

%token <tok> CONTROL ALLOW LISTEN_ON

%token <tok> LOG
%token <tok> LOG_DEST
%token <tok> LOG_SRC
%token <tok> LOG_LEVEL

%%

config: conf_entries END { return 0; } ;

conf_entries:
 /* EMPTY */
 | conf_entries conf
 ;

interface_start:
 | TEXT
 | REMOTES
 | LOG_SRC
 | LOG
 | LOG_LEVEL
 | CONTROL
 ;

interface:
 | interface PORT NUM ';'		{ _port = $3.i; }
 | interface ADDRESS IPA ';'		{ _addr = $3.t; }
 | interface ADDRESS IPA '@' NUM ';'	{ _addr = $3.t; _port = $5.i;  }
 | interface ADDRESS IPA6 ';'		{ _addr = $3.t; }
 | interface ADDRESS IPA6 '@' NUM ';'	{ _addr = $3.t; _port = $5.i; }
 ;

interfaces:
   INTERFACES '{'			{ f_section(scanner, 2, C_SERVER); }
 | interfaces interface_start '{'	{ f_name(scanner, 1, C_LISTEN, false); _addr = NULL, _port = -1; }
   interface '}' {
 	if (_addr == NULL) {
        	cf_error(scanner, "interface.listen address not defined");
	} else if (_port == -1) {
        	f_val(scanner, 1, false, "%s\n", _addr);
	} else {
        	f_val(scanner, 1, false, "%s@%i\n", _addr, _port);
	}
   }
 ;

system:
   SYSTEM '{'				{ f_section(scanner, 1, C_SERVER); }
 | system SVERSION TEXT ';'		{ f_quote(scanner, 1, C_VERSION, $3.t); }
 | system SVERSION BOOL ';'		{ f_auto_str(scanner, 1, C_VERSION, $3.i); }
 | system IDENTITY TEXT ';'		{ f_quote(scanner, 1, C_IDENT, $3.t); }
 | system IDENTITY BOOL ';'		{ f_auto_str(scanner, 1, C_IDENT, $3.i); }
 | system NSID TEXT ';'			{ f_quote(scanner, 1, C_NSID,  $3.t); }
 | system NSID BOOL ';'			{ f_auto_str(scanner, 1, C_NSID, $3.i); }
 | system MAX_UDP_PAYLOAD NUM ';'	{ f_int(scanner, 1, C_MAX_UDP_PAYLOAD, $3.i); }
 | system RUNDIR TEXT ';'		{ f_quote(scanner, 1, C_RUNDIR, $3.t); }
 | system PIDFILE TEXT ';'		{ f_quote(scanner, 1, C_PIDFILE, $3.t); }
 | system WORKERS NUM ';'		{ f_int(scanner, 1, C_WORKERS, $3.i); }
 | system BACKGROUND_WORKERS NUM ';'	{ f_int(scanner, 1, C_BG_WORKERS, $3.i); }
 | system ASYNC_START BOOL ';'		{ f_bool(scanner, 1, C_ASYNC_START, $3.i); }
 | system MAX_CONN_IDLE INTERVAL ';'	{ f_int(scanner, 1, C_MAX_CONN_IDLE, $3.i); }
 | system MAX_CONN_HS INTERVAL ';'	{ f_int(scanner, 1, C_MAX_CONN_HANDSHAKE, $3.i); }
 | system MAX_CONN_REPLY INTERVAL ';'	{ f_int(scanner, 1, C_MAX_CONN_REPLY, $3.i); }
 | system MAX_TCP_CLIENTS NUM ';'	{ f_int(scanner, 1, C_MAX_TCP_CLIENTS, $3.i); }
 | system RATE_LIMIT NUM ';'		{ f_int(scanner, 1, C_RATE_LIMIT, $3.i); }
 | system RATE_LIMIT_SIZE SIZE ';'	{ f_int(scanner, 1, C_RATE_LIMIT_SIZE, $3.l); }
 | system RATE_LIMIT_SIZE NUM ';'	{ f_int(scanner, 1, C_RATE_LIMIT_SIZE, $3.i); }
 | system RATE_LIMIT_SLIP NUM ';'	{ f_int(scanner, 1, C_RATE_LIMIT_SLIP, $3.i); }
 | system TRANSFERS NUM ';'		{ f_int(scanner, 1, C_TRANSFERS, $3.i); }
 | system USER TEXT ';' {
 	char *sep = strchr($3.t, '.');
 	if (sep != NULL) {
 		*sep = ':';
 	}
 	f_str(scanner, 1, C_USER, $3.t);
   }
 | system HOSTNAME TEXT ';' {
     cf_warning(scanner, "option 'system.hostname' is deprecated, "
                         "use 'system.identity' instead");
   }
 | system STORAGE TEXT ';' {
     cf_warning(scanner, "option 'system.storage' was relocated, "
                         "use 'zones.storage' instead");
   }
 | system KEY TSIG_ALGO_NAME TEXT ';' {
     cf_warning(scanner, "option 'system.key' is deprecated and "
                         "it has no effect");
   }
 ;

keys:
   KEYS '{'				{ f_section(scanner, 1, C_KEY); }
 | keys TEXT TSIG_ALGO_NAME TEXT ';' {
	f_id(scanner, 1, C_ID, $2.t);
	f_str(scanner, 1, C_ALG, $3.t);
	f_quote(scanner, 1, C_SECRET, $4.t);
   }
 ;

remote_start:
 | TEXT					{ f_id(scanner, 1, C_ID, $1.t); }
 | LOG_SRC				{ f_id(scanner, 1, C_ID, $1.t); }
 | LOG					{ f_id(scanner, 1, C_ID, $1.t); }
 | LOG_LEVEL				{ f_id(scanner, 1, C_ID, $1.t); }
 | CONTROL				{ f_id(scanner, 1, C_ID, $1.t); }
 ;

remote:
 | remote PORT NUM ';'			{ _port = $3.i; }
 | remote ADDRESS IPA ';'		{ _addr = $3.t; }
 | remote ADDRESS IPA '@' NUM ';'	{ _addr = $3.t; _port = $5.i;  }
 | remote ADDRESS IPA6 ';'		{ _addr = $3.t; }
 | remote ADDRESS IPA6 '@' NUM ';'	{ _addr = $3.t; _port = $5.i; }
 | remote ADDRESS IPA '/' NUM ';'	{ _addr = $3.t;
// TODO
   }
 | remote ADDRESS IPA6 '/' NUM ';' {
// TODO
 }
 | remote KEY TEXT ';'			{ f_str(scanner, 1, C_KEY, $3.t); }
 | remote VIA IPA ';'			{ f_str(scanner, 1, C_VIA, $3.t); }
 | remote VIA IPA6 ';'			{ f_str(scanner, 1, C_VIA, $3.t); }
 | remote VIA TEXT ';' {
     cf_warning(scanner, "interface name in 'via' option is not valid in the new "
                "format, use address specification instead (see documentation)");
   }
 ;

remotes:
   REMOTES '{'				{ f_section(scanner, 1, C_RMT); }
 | remotes remote_start '{'		{ _addr = NULL, _port = -1; }
   remote '}' {
 	if (_addr == NULL) {
        	cf_error(scanner, "remote.address not defined");
	} else if (_port == -1) {
        	f_name(scanner, 1, C_ADDR, false);
        	f_val(scanner, 1, false, "%s\n", _addr);
	} else {
        	f_name(scanner, 1, C_ADDR, false);
        	f_val(scanner, 1, false, "%s@%i\n", _addr, _port);
        }
 }
 ;

group_member:
 TEXT
 ;

group:
 /* empty */
 | group_member
 | group ',' group_member
 ;

group_start:
 TEXT
 ;

groups:
   GROUPS '{' {
     cf_warning(scanner, "group section is not valid in the new format, "
                "use zone template instead (see documentation)");
   }
 | groups group_start '{' group '}'
 ;

zone_acl_start:
   XFR_IN { f_name(scanner, 1, C_MASTER, false);
   }
 | XFR_OUT { f_name(scanner, 1, C_ACL, false);
   }
 | NOTIFY_IN { f_name(scanner, 1, C_ACL, false);
   }
 | NOTIFY_OUT { f_name(scanner, 1, C_NOTIFY, false);
   }
 | UPDATE_IN { f_name(scanner, 1, C_ACL, false);
 }
 ;

zone_acl_item:
 | TEXT      { f_val(scanner, 1, false, "%s\n", $1.t); }
 | LOG_SRC   { f_val(scanner, 1, false, "%s\n", $1.t); }
 | LOG       { f_val(scanner, 1, false, "%s\n", $1.t); }
 | LOG_LEVEL { f_val(scanner, 1, false, "%s\n", $1.t); }
 | CONTROL   { f_val(scanner, 1, false, "%s\n", $1.t); }
 ;

zone_acl_list:
 | zone_acl_list zone_acl_item ','
 | zone_acl_list zone_acl_item ';'
 ;

zone_acl:
 | zone_acl TEXT ';' {
   }
 ;

query_module:
 TEXT TEXT
 ;

query_module_list:
 | query_module ';' query_module_list
 ;

zone_start:
 | USER					{ f_id(scanner, 1, C_DOMAIN, $1.t); }
 | REMOTES				{ f_id(scanner, 1, C_DOMAIN, $1.t); }
 | LOG_SRC				{ f_id(scanner, 1, C_DOMAIN, $1.t); }
 | LOG					{ f_id(scanner, 1, C_DOMAIN, $1.t); }
 | LOG_LEVEL				{ f_id(scanner, 1, C_DOMAIN, $1.t); }
 | CONTROL				{ f_id(scanner, 1, C_DOMAIN, $1.t); }
 | NUM '/' TEXT				{
      f_name(scanner, 1, C_DOMAIN, true);
      f_val(scanner, 1, false, "%i/%s", $1.i, $3.t);
      f_val(scanner, 1, false, "\n");
   }
 | TEXT					{ f_id(scanner, 1, C_DOMAIN, $1.t); }
 ;

zone:
   zone_start '{'
 | zone zone_acl_start '{' zone_acl '}'
 | zone zone_acl_start zone_acl_list
 | zone FILENAME TEXT ';'			{ f_quote(scanner, 1, C_FILE, $3.t); }
 | zone DISABLE_ANY BOOL ';'			{ f_bool(scanner, 1, C_DISABLE_ANY, $3.i); }
 | zone BUILD_DIFFS BOOL ';'			{ f_bool(scanner, 1, C_IXFR_DIFF, $3.i); }
 | zone SEMANTIC_CHECKS BOOL ';'		{ f_bool(scanner, 1, C_SEM_CHECKS, $3.i); }
 | zone IXFR_FSLIMIT SIZE ';'			{ f_int(scanner, 1, C_IXFR_FSLIMIT, $3.l); }
 | zone IXFR_FSLIMIT NUM ';'			{ f_int(scanner, 1, C_IXFR_FSLIMIT, $3.i); }
 | zone NOTIFY_RETRIES NUM ';'			{ f_int(scanner, 1, C_NOTIFY_RETRIES, $3.i); }
 | zone NOTIFY_TIMEOUT NUM ';'			{ f_int(scanner, 1, C_NOTIFY_TIMEOUT, $3.i); }
 | zone DBSYNC_TIMEOUT NUM ';'			{ f_int(scanner, 1, C_ZONEFILE_SYNC, $3.i); }
 | zone DBSYNC_TIMEOUT INTERVAL ';'		{ f_int(scanner, 1, C_ZONEFILE_SYNC, $3.i); }
 | zone STORAGE TEXT ';'			{ f_quote(scanner, 1, C_STORAGE, $3.t); }
 | zone DNSSEC_ENABLE BOOL ';'			{ f_bool(scanner, 1, C_DNSSEC_ENABLE, $3.i); }
 | zone DNSSEC_KEYDIR TEXT ';'			{ f_quote(scanner, 1, C_DNSSEC_KEYDIR, $3.t); }
 | zone SIGNATURE_LIFETIME NUM ';'		{ f_int(scanner, 1, C_SIG_LIFETIME, $3.i); }
 | zone SIGNATURE_LIFETIME INTERVAL ';'		{ f_int(scanner, 1, C_SIG_LIFETIME, $3.i); }
 | zone SERIAL_POLICY SERIAL_POLICY_VAL ';'	{ f_str(scanner, 1, C_SERIAL_POLICY, $3.t); }
 | zone QUERY_MODULE '{' {

   }
   query_module_list '}'
 ;

query_genmodule:
 TEXT TEXT
 ;
query_genmodule_list:
 | query_genmodule ';' query_genmodule_list
 ;

zones:
   ZONES '{'					{ f_section(scanner, 1, C_ZONE); }
 | zones zone '}'
 | zones DISABLE_ANY BOOL ';'			{ f_bool(scanner, 1, C_DISABLE_ANY, $3.i); }
 | zones BUILD_DIFFS BOOL ';'			{ f_bool(scanner, 1, C_IXFR_DIFF, $3.i); }
 | zones SEMANTIC_CHECKS BOOL ';'		{ f_bool(scanner, 1, C_SEM_CHECKS, $3.i); }
 | zones IXFR_FSLIMIT SIZE ';'			{ f_int(scanner, 1, C_IXFR_FSLIMIT, $3.l); }
 | zones IXFR_FSLIMIT NUM ';'			{ f_int(scanner, 1, C_IXFR_FSLIMIT, $3.i); }
 | zones NOTIFY_RETRIES NUM ';'			{ f_int(scanner, 1, C_NOTIFY_RETRIES, $3.i); }
 | zones NOTIFY_TIMEOUT NUM ';'			{ f_int(scanner, 1, C_NOTIFY_TIMEOUT, $3.i); }
 | zones DBSYNC_TIMEOUT NUM ';'			{ f_int(scanner, 1, C_ZONEFILE_SYNC, $3.i); }
 | zones DBSYNC_TIMEOUT INTERVAL ';'		{ f_int(scanner, 1, C_ZONEFILE_SYNC, $3.i); }
 | zones STORAGE TEXT ';'			{ f_quote(scanner, 1, C_STORAGE, $3.t); }
 | zones DNSSEC_ENABLE BOOL ';'			{ f_bool(scanner, 1, C_DNSSEC_ENABLE, $3.i); }
 | zones DNSSEC_KEYDIR TEXT ';'			{ f_quote(scanner, 1, C_DNSSEC_KEYDIR, $3.t); }
 | zones SIGNATURE_LIFETIME NUM ';'		{ f_int(scanner, 1, C_SIG_LIFETIME, $3.i); }
 | zones SIGNATURE_LIFETIME INTERVAL ';'	{ f_int(scanner, 1, C_SIG_LIFETIME, $3.i); }
 | zones SERIAL_POLICY SERIAL_POLICY_VAL ';'	{ f_str(scanner, 1, C_SERIAL_POLICY, $3.t); }
 | zones QUERY_MODULE '{' {

   }
   query_genmodule_list '}'
 ;

log_prios:
 | log_prios LOG_LEVEL ',' { if (_str == NULL) _str = $2.t; }
 | log_prios LOG_LEVEL ';' { if (_str == NULL) _str = $2.t; }
 ;

log_src:
 | log_src LOG_SRC {
     f_name(scanner, 1, $2.t, false);
     _str = NULL;
   }
   log_prios {
     f_val(scanner, 1, false, "%s\n", _str);
   }
 ;

log_dest:
   LOG_DEST { f_id(scanner, 1, C_TO, $1.t); }
;

log_file:
   FILENAME TEXT {
      f_name(scanner, 1, C_TO, true);
      f_val(scanner, 1, true, "%s", $2.t);
      f_val(scanner, 1, false, "\n");
   }
;

log_start:
 | log_start log_dest '{' log_src '}'
 | log_start log_file '{' log_src '}'
 ;

log:
   LOG '{'				{ f_section(scanner, 1, C_LOG); }
   log_start
 ;

ctl_listen_start:
  LISTEN_ON
  ;

ctl_allow_start:
  ALLOW
  ;

control:
   CONTROL '{'				{ f_section(scanner, 1, C_CTL); }
 | control ctl_listen_start '{'		{ f_name(scanner, 1, C_LISTEN, false); _addr = NULL, _port = -1; }
   interface '}' {
 	if (_addr == NULL) {
        	cf_error(scanner, "control.listen address not defined");
	} else if (_port == -1) {
        	f_val(scanner, 1, false, "%s\n", _addr);
	} else {
        	f_val(scanner, 1, false, "%s@%i\n", _addr, _port);
	}
   }
 | control ctl_listen_start TEXT ';'	{ f_quote(scanner, 1, C_LISTEN, $3.t); }
 | control ctl_allow_start '{' zone_acl '}'
 | control ctl_allow_start zone_acl_list
 ;

conf: ';' | system '}' | interfaces '}' | keys '}' | remotes '}' | groups '}' | zones '}' | log '}' | control '}';

%%
