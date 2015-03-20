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

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "knot/conf/extra.h"

static int run_parser(FILE *out, const char *file_in, int run_count)
{
	extern int cf_parse(void *scanner);
	extern int cf_lex_init_extra(void *, void *scanner);
	extern void cf_set_in(FILE *f, void *scanner);
	extern void cf_lex_destroy(void *scanner);
	extern volatile int parser_ret;

	FILE *in = fopen(file_in, "r");
	if (in == NULL) {
		printf("Failed to open input file '%s'\n", file_in);
		return -1;
	}

	void *sc = NULL;
	conf_extra_t *extra = conf_extra_init(file_in, run_count);
	cf_lex_init_extra(extra, &sc);
	cf_set_in(in, sc);
	cf_parse(sc);
	cf_lex_destroy(sc);
	conf_extra_free(extra);

	fclose(in);

	return parser_ret;
}

static int convert(const char *file_out, const char *file_in)
{
	FILE *out = fopen(file_out, "w");
	if (out == NULL) {
		printf("Failed to open output file '%s'\n", file_out);
		return -1;
	}

	// Parse the input file multiple times to get some context.
	for (int i = 1; i <= 2; i++) {
		int ret = run_parser(out, file_in, i);
		if (ret != 0) {
			fclose(out);
			return ret;
		}
	}

	fclose(out);

	return 0;
}

void help(void)
{
	printf("Usage: knotconf1to2 -i confv1.conf -o confv2.conf\n");
	printf("\nParameters:\n"
	       " -i, --in <file>      Input config file (Knot 1.x)\n"
	       " -o, --out <file>     Output config file (Knot 2.x)\n"
	       " -V, --version        Print package version.\n"
	       " -h, --help           Print help and usage.\n");
}

int main(int argc, char **argv)
{
	int c = 0, li = 0;
	const char *file_in = NULL;
	const char *file_out = NULL;

	struct option opts[] = {
		{ "in",      required_argument, NULL, 'i' },
		{ "out",     required_argument, NULL, 'o' },
		{ "version", no_argument,       NULL, 'V' },
		{ "help",    no_argument,       NULL, 'h' },
		{ NULL }
	};

	// Parse parameters.
	while ((c = getopt_long(argc, argv, "i:o:Vh", opts, &li)) != -1) {
		switch (c)
		{
		case 'i':
			file_in = optarg;
			break;
		case 'o':
			file_out = optarg;
			break;
		case 'V':
			printf("%s, version %s\n", "Knot DNS", PACKAGE_VERSION);
			return EXIT_SUCCESS;
		case 'h':
		case '?':
			help();
			return EXIT_SUCCESS;
		default:
			help();
			return EXIT_FAILURE;
		}
	}

	// Check for missing or invalid parameters.
	if (argc - optind > 0 || file_in == NULL || file_out == NULL) {
		help();
		return EXIT_FAILURE;
	}

	// Convert the file.
	int ret = convert(file_out, file_in);
	if (ret != 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
