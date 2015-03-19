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

#include "knot/conf/conf.h"

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
	const char *in = NULL;
	const char *out = NULL;

	struct option opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"version", no_argument,       0, 'V'},
		{"help",    no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	// Parse parameters.
	while ((c = getopt_long(argc, argv, "i:o:Vh", opts, &li)) != -1) {
		switch (c)
		{
		case 'i':
			in = optarg;
			break;
		case 'o':
			out = optarg;
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
	if (argc - optind > 0 || in == NULL || out == NULL) {
		help();
		return EXIT_FAILURE;
	}

	// Open output file.
	FILE *fout = fopen(out, "w");
	if (fout == NULL) {
		printf("Failed to open output file '%s'\n", out);
		return EXIT_FAILURE;
	}

	// Parse the configuration.
	int ret = conf_fparser(in);
	if (ret != 0) {
		return EXIT_FAILURE;
	}

	fclose(fout);

	return EXIT_SUCCESS;
}
