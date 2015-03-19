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
 * \file cf-parse.y
 *
 * \author Ondrej Sury <ondrej.sury@nic.cz>
 *
 * \brief Server configuration structures and API.
 */
%{

#include <config.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#include "knot/conf/scheme.h"
#include "dnssec/binary.h"
#include "dnssec/tsig.h"
#include "libknot/internal/sockaddr.h"
#include "libknot/internal/strlcat.h"
#include "libknot/internal/strlcpy.h"
#include "libknot/dname.h"
#include "libknot/binary.h"
#include "libknot/rrtype/opt.h"
#include "knot/server/rrl.h"
#include "knot/conf/conf.h"
#include "knot/conf/extra.h"
#include "knot/conf/libknotd_la-cf-parse.h" /* Automake generated header. */

extern int cf_lex (YYSTYPE *lvalp, void *scanner);
static conf_zone_t *this_zone = 0;
static list_t *this_list = 0;
static conf_log_t *this_log = 0;
static conf_log_map_t *this_logmap = 0;
//#define YYERROR_VERBOSE 1

#define DEFAULT_PORT		53
#define DEFAULT_CTL_PORT	5533

static char *_addr = NULL;
static int _port = -1;


#define ERROR_BUFFER_SIZE       512 /*!< \brief Error buffer size. */
extern int cf_get_lineno(void *scanner);
extern char *cf_get_text(void *scanner);
extern conf_extra_t *cf_get_extra(void *scanner);
extern int cf_lex_init_extra(void *, void *scanner);
volatile int _parser_res = 0; /*!< \brief Parser result. */
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
		extra->error = true;
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
	_parser_res = KNOT_EPARSEFAIL;
}

void cf_warning(void *scanner, const char *format, ...)
{
	char buffer[ERROR_BUFFER_SIZE];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	cf_print_error(scanner, "Warning", buffer);
	_parser_res = KNOT_EPARSEFAIL;
}

void dump_name(const char *name)
{
	printf("    %s: ", name + 1);
}

void dump_value(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

void dump_section(const char *name)
{
	printf("\n%s:\n", name + 1);
}

void dump_id(const char *name, const char *value)
{
	printf("  - %s: %s\n", name + 1, value);
}

void dump_quote(const char *name, const char *value)
{
	dump_name(name);
	dump_value("\"%s\"\n", value);
}

void dump_str(const char *name, const char *value)
{
	dump_name(name);
	dump_value("%s\n", value);
}

void dump_auto_str(const char *name, int value)
{
	if (value == 0) {
		dump_name(name);
		dump_value("\"\"\n");
	}
}

void dump_int(const char *name, int value)
{
	dump_name(name);
	dump_value("%i\n", value);
}

void dump_bool(const char *name, int value)
{
	dump_name(name);
	dump_value("%s\n", value == 1 ? "on" : "off");
}

void dump_note(const char *format, ...)
{
	dump_value("# ");
	dump_value(format);
	dump_value("\n");
}

static void conf_acl_item(void *scanner, char *item)
{
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
		dnssec_tsig_algorithm_t alg;
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
   INTERFACES '{'			{ dump_section(C_SERVER); }
 | interfaces interface_start '{'	{ dump_name(C_LISTEN); _addr = NULL, _port = -1; }
   interface '}' {
 	if (_addr == NULL) {
        	cf_error(scanner, "interface.listen address not defined");
	} else if (_port == -1) {
        	dump_value("%s\n", _addr);
	} else {
        	dump_value("%s@%i\n", _addr, _port);
	}
   }
 ;

system:
   SYSTEM '{'				{ dump_section(C_SERVER); }
 | system SVERSION TEXT ';'		{ dump_quote(C_VERSION, $3.t); }
 | system SVERSION BOOL ';'		{ dump_auto_str(C_VERSION, $3.i); }
 | system IDENTITY TEXT ';'		{ dump_quote(C_IDENT, $3.t); }
 | system IDENTITY BOOL ';'		{ dump_auto_str(C_IDENT, $3.i); }
 | system NSID TEXT ';'			{ dump_quote(C_NSID,  $3.t); }
 | system NSID BOOL ';'			{ dump_auto_str(C_NSID, $3.i); }
 | system MAX_UDP_PAYLOAD NUM ';'	{ dump_int(C_MAX_UDP_PAYLOAD, $3.i); }
 | system RUNDIR TEXT ';'		{ dump_quote(C_RUNDIR, $3.t); }
 | system PIDFILE TEXT ';'		{ dump_quote(C_PIDFILE, $3.t); }
 | system WORKERS NUM ';'		{ dump_int(C_WORKERS, $3.i); }
 | system BACKGROUND_WORKERS NUM ';'	{ dump_int(C_BG_WORKERS, $3.i); }
 | system ASYNC_START BOOL ';'		{ dump_bool(C_ASYNC_START, $3.i); }
 | system MAX_CONN_IDLE INTERVAL ';'	{ dump_int(C_MAX_CONN_IDLE, $3.i); }
 | system MAX_CONN_HS INTERVAL ';'	{ dump_int(C_MAX_CONN_HANDSHAKE, $3.i); }
 | system MAX_CONN_REPLY INTERVAL ';'	{ dump_int(C_MAX_CONN_REPLY, $3.i); }
 | system MAX_TCP_CLIENTS NUM ';'	{ dump_int(C_MAX_TCP_CLIENTS, $3.i); }
 | system RATE_LIMIT NUM ';'		{ dump_int(C_RATE_LIMIT, $3.i); }
 | system RATE_LIMIT_SIZE SIZE ';'	{ dump_int(C_RATE_LIMIT_SIZE, $3.l); }
 | system RATE_LIMIT_SIZE NUM ';'	{ dump_int(C_RATE_LIMIT_SIZE, $3.i); }
 | system RATE_LIMIT_SLIP NUM ';'	{ dump_int(C_RATE_LIMIT_SLIP, $3.i); }
 | system TRANSFERS NUM ';'		{ dump_int(C_TRANSFERS, $3.i); }
 | system USER TEXT ';' {
 	char *sep = strchr($3.t, '.');
 	if (sep != NULL) {
 		*sep = ':';
 	}
 	dump_str(C_USER, $3.t);
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
   KEYS '{'				{ dump_section(C_KEY); }
 | keys TEXT TSIG_ALGO_NAME TEXT ';' {
	dump_id(C_ID, $2.t);
	dump_str(C_ALG, $3.t);
	dump_quote(C_SECRET, $4.t);
   }
 ;

remote_start:
 | TEXT					{ dump_id(C_ID, $1.t); }
 | LOG_SRC				{ dump_id(C_ID, $1.t); }
 | LOG					{ dump_id(C_ID, $1.t); }
 | LOG_LEVEL				{ dump_id(C_ID, $1.t); }
 | CONTROL				{ dump_id(C_ID, $1.t); }
 ;

remote:
 | remote PORT NUM ';'			{ _port = $3.i; }
 | remote ADDRESS IPA ';'		{ _addr = $3.t; }
 | remote ADDRESS IPA '@' NUM ';'	{ _addr = $3.t; _port = $5.i;  }
 | remote ADDRESS IPA6 ';'		{ _addr = $3.t; }
 | remote ADDRESS IPA6 '@' NUM ';'	{ _addr = $3.t; _port = $5.i; }
 | remote ADDRESS IPA '/' NUM ';'	{ _addr = $3.t;
     dump_note("subnet definition '/%i' is no longer valid in the new format, "
               "use ACL section instead", $5.i);
     cf_warning(scanner, "subnet definition is not valid in the new format "
                "(see documentation)");
   }
 | remote ADDRESS IPA6 '/' NUM ';' {
     dump_note("subnet definition '/%i' is no longer valid in the new format, "
               "use ACL section instead", $5.i);
     cf_warning(scanner, "subnet definition is not valid in the new format "
                "(see documentation)");
   }
 | remote KEY TEXT ';'			{ dump_str(C_KEY, $3.t); }
 | remote VIA IPA ';'			{ dump_str(C_VIA, $3.t); }
 | remote VIA IPA6 ';'			{ dump_str(C_VIA, $3.t); }
 | remote VIA TEXT ';' {
     cf_warning(scanner, "interface name in 'via' option is not valid in the new "
                "format, use address specification instead (see documentation)");
   }
 ;

remotes:
   REMOTES '{'				{ dump_section(C_RMT); }
 | remotes remote_start '{'		{ _addr = NULL, _port = -1; }
   remote '}' {
 	if (_addr == NULL) {
        	cf_error(scanner, "remote.address not defined");
	} else if (_port == -1) {
        	dump_name(C_ADDR);
        	dump_value("%s\n", _addr);
	} else {
        	dump_name(C_ADDR);
        	dump_value("%s@%i\n", _addr, _port);
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
   XFR_IN {
      this_list = &this_zone->acl.xfr_in;
   }
 | XFR_OUT {
      this_list = &this_zone->acl.xfr_out;
   }
 | NOTIFY_IN {
      this_list = &this_zone->acl.notify_in;
   }
 | NOTIFY_OUT {
      this_list = &this_zone->acl.notify_out;
   }
 | UPDATE_IN {
      this_list = &this_zone->acl.update_in;
 }
 ;

zone_acl_item:
 | TEXT { conf_acl_item(scanner, $1.t); }
 | LOG_SRC  { conf_acl_item(scanner, strdup($1.t)); }
 | LOG  { conf_acl_item(scanner, strdup($1.t)); }
 | LOG_LEVEL  { conf_acl_item(scanner, strdup($1.t)); }
 | CONTROL    { conf_acl_item(scanner, strdup($1.t)); }
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
 | USER					{ dump_id(C_DOMAIN, $1.t); }
 | REMOTES				{ dump_id(C_DOMAIN, $1.t); }
 | LOG_SRC				{ dump_id(C_DOMAIN, $1.t); }
 | LOG					{ dump_id(C_DOMAIN, $1.t); }
 | LOG_LEVEL				{ dump_id(C_DOMAIN, $1.t); }
 | CONTROL				{ dump_id(C_DOMAIN, $1.t); }
 | NUM '/' TEXT				{ /*dump_id(C_DOMAIN, "%s/%s", $1.t, $3.t);*/ }
 | TEXT					{ dump_id(C_DOMAIN, $1.t); }
 ;

zone:
   zone_start '{'
 | zone zone_acl_start '{' zone_acl '}'
 | zone zone_acl_start zone_acl_list
 | zone FILENAME TEXT ';'			{ dump_quote(C_FILE, $3.t); }
 | zone DISABLE_ANY BOOL ';'			{ dump_bool(C_DISABLE_ANY, $3.i); }
 | zone BUILD_DIFFS BOOL ';'			{ dump_bool(C_IXFR_DIFF, $3.i); }
 | zone SEMANTIC_CHECKS BOOL ';'		{ dump_bool(C_SEM_CHECKS, $3.i); }
 | zone IXFR_FSLIMIT SIZE ';'			{ dump_int(C_IXFR_FSLIMIT, $3.l); }
 | zone IXFR_FSLIMIT NUM ';'			{ dump_int(C_IXFR_FSLIMIT, $3.i); }
 | zone NOTIFY_RETRIES NUM ';'			{ dump_int(C_NOTIFY_RETRIES, $3.i); }
 | zone NOTIFY_TIMEOUT NUM ';'			{ dump_int(C_NOTIFY_TIMEOUT, $3.i); }
 | zone DBSYNC_TIMEOUT NUM ';'			{ dump_int(C_ZONEFILE_SYNC, $3.i); }
 | zone DBSYNC_TIMEOUT INTERVAL ';'		{ dump_int(C_ZONEFILE_SYNC, $3.i); }
 | zone STORAGE TEXT ';'			{ dump_quote(C_STORAGE, $3.t); }
 | zone DNSSEC_ENABLE BOOL ';'			{ dump_bool(C_DNSSEC_ENABLE, $3.i); }
 | zone DNSSEC_KEYDIR TEXT ';'			{ dump_quote(C_DNSSEC_KEYDIR, $3.t); }
 | zone SIGNATURE_LIFETIME NUM ';'		{ dump_int(C_SIG_LIFETIME, $3.i); }
 | zone SIGNATURE_LIFETIME INTERVAL ';'		{ dump_int(C_SIG_LIFETIME, $3.i); }
 | zone SERIAL_POLICY SERIAL_POLICY_VAL ';'	{ dump_str(C_SERIAL_POLICY, $3.t); }
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
   ZONES '{'					{ dump_section(C_ZONE); }
 | zones zone '}'
 | zones DISABLE_ANY BOOL ';'			{ dump_bool(C_DISABLE_ANY, $3.i); }
 | zones BUILD_DIFFS BOOL ';'			{ dump_bool(C_IXFR_DIFF, $3.i); }
 | zones SEMANTIC_CHECKS BOOL ';'		{ dump_bool(C_SEM_CHECKS, $3.i); }
 | zones IXFR_FSLIMIT SIZE ';'			{ dump_int(C_IXFR_FSLIMIT, $3.l); }
 | zones IXFR_FSLIMIT NUM ';'			{ dump_int(C_IXFR_FSLIMIT, $3.i); }
 | zones NOTIFY_RETRIES NUM ';'			{ dump_int(C_NOTIFY_RETRIES, $3.i); }
 | zones NOTIFY_TIMEOUT NUM ';'			{ dump_int(C_NOTIFY_TIMEOUT, $3.i); }
 | zones DBSYNC_TIMEOUT NUM ';'			{ dump_int(C_ZONEFILE_SYNC, $3.i); }
 | zones DBSYNC_TIMEOUT INTERVAL ';'		{ dump_int(C_ZONEFILE_SYNC, $3.i); }
 | zones STORAGE TEXT ';'			{ dump_quote(C_STORAGE, $3.t); }
 | zones DNSSEC_ENABLE BOOL ';'			{ dump_bool(C_DNSSEC_ENABLE, $3.i); }
 | zones DNSSEC_KEYDIR TEXT ';'			{ dump_quote(C_DNSSEC_KEYDIR, $3.t); }
 | zones SIGNATURE_LIFETIME NUM ';'		{ dump_int(C_SIG_LIFETIME, $3.i); }
 | zones SIGNATURE_LIFETIME INTERVAL ';'	{ dump_int(C_SIG_LIFETIME, $3.i); }
 | zones SERIAL_POLICY SERIAL_POLICY_VAL ';'	{ dump_str(C_SERIAL_POLICY, $3.t); }
 | zones QUERY_MODULE '{' {

   }
   query_genmodule_list '}'
 ;

log_prios_start: {
  this_logmap = malloc(sizeof(conf_log_map_t));
  this_logmap->source = 0;
  this_logmap->prios = 0;
  add_tail(&this_log->map, &this_logmap->n);
}
;

log_prios:
   log_prios_start
 | log_prios LOG_LEVEL ',' { this_logmap->prios |= $2.i;
	cf_warning(scanner, "multiple log severities are deprecated, "
	                    "using the least serious one");
 }
 | log_prios LOG_LEVEL ';' { this_logmap->prios |= $2.i; }
 ;

log_src:
 | log_src LOG_SRC log_prios {
     this_logmap->source = $2.i;
     this_logmap = 0;
   }
 ;

log_dest: LOG_DEST {
}
;

log_file: FILENAME TEXT {
}
;

log_end: {
}
;

log_start:
 | log_start log_dest '{' log_src '}'
 | log_start log_file '{' log_src '}'
 ;

log: LOG { } '{' log_start log_end
 ;

ctl_listen_start:
  LISTEN_ON
  ;

ctl_allow_start:
  ALLOW
  ;

control:
   CONTROL '{'				{ dump_section(C_CTL); }
 | control ctl_listen_start '{'		{ dump_name(C_LISTEN); _addr = NULL, _port = DEFAULT_CTL_PORT; }
   interface '}' {
 	if (_addr == NULL) {
        	cf_error(scanner, "control.listen address not defined");
	} else {
        	dump_value("%s@%i\n", _addr, _port);
	}
   }
 | control ctl_listen_start TEXT ';'	{ dump_quote(C_LISTEN, $3.t); }
 | control ctl_allow_start '{' zone_acl '}'
 | control ctl_allow_start zone_acl_list
 ;

conf: ';' | system '}' | interfaces '}' | keys '}' | remotes '}' | groups '}' | zones '}' | log '}' | control '}';

%%
