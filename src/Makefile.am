ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
SUBDIRS = .

# $(YACC) will generate header file
AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-DCONFIG_DIR='"${config_dir}"'		\
	-DSTORAGE_DIR='"${storage_dir}"'	\
	-DRUN_DIR='"${run_dir}"'

AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)
AM_YFLAGS = -pcf_ -d

sbin_PROGRAMS = knotconf1to2

BUILT_SOURCES =					\
	knot/conf/cf-lex.c			\
	knot/conf/cf-parse.c			\
	knot/conf/cf-parse.h

CLEANFILES =					\
	knot/conf/cf-lex.c			\
	knot/conf/cf-parse.c			\
	knot/conf/cf-parse.h

knotconf1to2_SOURCES =				\
	knot/conf/cf-lex.l			\
	knot/conf/cf-parse.y			\
	knot/conf/extra.c			\
	knot/conf/extra.h			\
	knot/conf/scheme.h			\
	knot/conf/includes.c			\
	knot/conf/includes.h			\
	knot/main.c
