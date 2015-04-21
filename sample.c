// Package: Crypto-PAn 1.0
// File: sample.c
// Last Update: April 2015
// Original Author: Jinliang Fan
// Author: Trevor Goodyear

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "panonymizer.h"

int main(int argc, char * argv[]) {
    // Provide your own 256-bit key here
    unsigned char my_key[32] = "inncinncinncinncinncinncinncinnc";

    FILE * f;
    unsigned int raw_addr, anonymized_addr;

    float packet_time;
    unsigned int packet_size, packet_addr1, packet_addr2, packet_addr3, packet_addr4, orig_addr1, orig_addr2, orig_addr3, orig_addr4;

    if (argc != 2) {
      fprintf(stderr, "usage: sample raw-trace-file\n");
      exit(-1);
    }
    
    if ((f = fopen(argv[1],"r")) == NULL) {
      fprintf(stderr,"Cannot open file %s\n", argv[1]);
      exit(-2);
    }
    
    printf("Raw \t\tSanitized \tRaw Int \tAnon Int\n");
    //readin and handle each line of the input file
    while  (fscanf(f, "%f", &packet_time) != EOF) {
    	fscanf(f, "%u", &packet_size);
        fscanf(f, "%u.%u.%u.%u", &orig_addr1, &orig_addr2, &orig_addr3, &orig_addr4);
      
    	//convert the raw IP from a.b.c.d format into unsigned int format.
    	raw_addr = (orig_addr1 << 24) + (orig_addr2 << 16) + (orig_addr3 << 8) + orig_addr4;

    	//Anonymize the raw IP
    	anonymized_addr = PAnonymizer_anonymize(my_key,raw_addr);

    	//convert the anonymized IP from unsigned int format to a.b.c.d format
    	packet_addr1 = anonymized_addr >> 24;
    	packet_addr2 = (anonymized_addr << 8) >> 24;
    	packet_addr3 = (anonymized_addr << 16) >> 24;
    	packet_addr4 = (anonymized_addr << 24) >> 24;

    	//output the sanitized trace
    	printf("%u.%u.%u.%u\t%u.%u.%u.%u\t%u\t%u\n",  orig_addr1, orig_addr2, orig_addr3, orig_addr4, packet_addr1, packet_addr2, packet_addr3, packet_addr4, raw_addr, anonymized_addr );
    }

}
