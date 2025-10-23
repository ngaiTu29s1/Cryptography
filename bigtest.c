/* 
 * Big test sosemanuk.h
 * Example: 
 * encrypt - ./bigtest -t 1 -b 1000000 -i file1 -o file2
 * decrypt - ./bigtest -t 2 -b 1000000 -i file2 -o file3
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include "sosemanuk.h"

#define MAX_FILE	4096

// Allocates memory
void *
xmalloc(size_t size)
{
	void *p = malloc(size);

	if(p == NULL) {
		printf("Allocates memory error!\n");
		exit(1);
	}
	else
		return p;
}

// Open the file
FILE *
open_file(char *s, int i)
{
	FILE *fp;
	
	if(i == 1)
		fp = fopen(s, "rb+");
	else
		fp = fopen(s, "w+");

	if(fp == NULL) {
		printf("Error open file!\n");
		exit(1);
	}

	return fp;
}

// Help function
void
help(void)
{
	printf("\nThis program is designed to encrypt/decrypt files.\n");
	printf("\nOptions:\n");
	printf("\t--help(-h) - reference manual\n");
	printf("\t--type(-t) - type running of program: 1 - encrypt, 2 - decrypt\n");
	printf("\t--block(-b) - block size data read from the file. By default = 10000\n");
	printf("\t--input(-i) - input file\n");
	printf("\t--output(-o) - output file\n");
	printf("Example: ./bigtest -t 1 -b 1000 -i 1.txt -o crypt or ./bigtest -t 2 -b 1000 -i crypt -o decrypt\n\n");
}

int
main(int argc, char *argv[])
{
	FILE *fp, *fd;
	struct sosemanuk_context ctx;
	uint32_t byte, block = 10000;
	uint8_t *buf, *out, key[32], iv[16];
	char file1[MAX_FILE], file2[MAX_FILE];
	int res, action = 1;

	const struct option long_option [] = {
		{"input",  1, NULL, 'i'},
		{"output", 1, NULL, 'o'},
		{"block",  1, NULL, 'b'},
		{"type",   1, NULL, 't'},
		{"help",   0, NULL, 'h'},
		{0, 	   0, NULL,  0 }
	};
	
	if(argc < 2) {
		help();
		return 0;
	}

	while((res = getopt_long(argc, argv, "i:o:b:t:h", long_option, 0)) != -1) {
		switch(res) {
		case 'b' : block = atoi(optarg);
			   break;
		case 'i' : strcpy(file1, optarg);
			   break;
		case 'o' : strcpy(file2, optarg);
			   break;
		case 't' : action = atoi(optarg);
			   break;
		case 'h' : help();
			   return 0;
		}
	}
	
	buf = xmalloc(sizeof(uint8_t) * block);
	out = xmalloc(sizeof(uint8_t) * block);
	
	fp = open_file(file1, 1);
	fd = open_file(file2, 2);
	
	memset(key, 'k', sizeof(key));
	memset(iv, 'i', sizeof(iv));

	if(sosemanuk_set_key_and_iv(&ctx, (uint8_t *)key, 32, iv, 16)) {
		printf("Mickey context filling error!\n");
		exit(1);
	}
	
	while((byte = fread(buf, 1, block, fp)) > 0) {
		if(action == 1)
			sosemanuk_crypt(&ctx, buf, byte, out);
		else
			sosemanuk_crypt(&ctx, buf, byte, out);
		
		fwrite(out, 1, byte, fd);
	}
	
	free(buf);
	free(out);

	return 0;
}

