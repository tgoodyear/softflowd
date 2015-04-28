//Package: Crypto-PAn 1.0
//File: panonymizer.h
//Last Update: April 11, 2002
//Author: Jinliang Fan

#ifndef _PANONYMIZER_H_
#define _PANONYMIZER_H_
#define ANONYMIZATION_KEY "inncinncinncinncinncinncinncinnc"

#include <mcrypt.h>

	uint32_t PAnonymizer_anonymize(const char * key,const uint32_t orig_addr);
    MCRYPT td, td2;
	
#endif
