// Package: Crypto-PAn 1.0
// File: panonymizer.cpp
// Last Update: April 17, 2002
// Author: Jinliang Fan

#define _PANONYMIZER_CPP_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "panonymizer.h"
#include <mcrypt.h>

//Anonymization funtion
uint32_t PAnonymizer_action(const char * key,const uint32_t orig_addr,int action) {
    
    char* IV = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    int keysize = 32;
    char* buffer;
    int buffer_len = 16;

    buffer = calloc(1, buffer_len);

    uint8_t m_pad[16] = {[0 ... 15] = 0};
    uint8_t rin_output[16];
    uint8_t rin_input[16];
    memcpy(rin_input, m_pad, 16);

    uint32_t result = 0;
    uint32_t first4bytes_pad, first4bytes_input;
    encrypt(m_pad,buffer_len,IV,key,keysize);
    first4bytes_pad = (((uint32_t) m_pad[0]) << 24) + (((uint32_t) m_pad[1]) << 16) + (((uint32_t) m_pad[2]) << 8) + (uint32_t) m_pad[3]; 

    int pos;
    // For each prefixes with length from 0 to 31, generate a bit using the Rijndael cipher,
    // which is used as a pseudorandom function here. The bits generated in every rounds
    // are combineed into a pseudorandom one-time-pad.
    for (pos = 0; pos <= 31 ; pos++) { 
        //Padding: The most significant pos bits are taken from orig_addr. The other 128-pos 
        //	   bits are taken from m_pad. The variables first4bytes_pad and first4bytes_input are used
        //	   to handle the annoying byte order problem.
        if (pos==0) {
          first4bytes_input =  first4bytes_pad; 
        }
        else {
          first4bytes_input = ((orig_addr >> (32-pos)) << (32-pos)) | ((first4bytes_pad<<pos) >> pos);
        }
        rin_input[0] = (uint8_t) (first4bytes_input >> 24);
        rin_input[1] = (uint8_t) ((first4bytes_input << 8) >> 24);
        rin_input[2] = (uint8_t) ((first4bytes_input << 16) >> 24);
        rin_input[3] = (uint8_t) ((first4bytes_input << 24) >> 24);

        int i;
        for(i=0;i<16;i++){
          rin_output[i] = rin_input[i];
        }
        //Encryption: The Rijndael cipher is used as pseudorandom function. During each 
        //round, only the first bit of rin_output is used.
        int r;
        if(action == 1) {
            r = encrypt(rin_output,buffer_len,IV,key,keysize);
        } else {
            r = decrypt(rin_output,buffer_len,IV,key,keysize);
        }
      	
        if(r != 0){
      		printf("Encrypt returned %d", r);
      	}
        
        //Combination: the bits are combined into a pseudorandom one-time-pad
        result |=  (rin_output[0] >> 7) << (31-pos);
    }
    //XOR the orginal address with the pseudorandom one-time-pad
    return result ^ orig_addr;
}

uint32_t PAnonymizer_anonymize(const char * key,const uint32_t orig_addr) {
    return PAnonymizer_action(key,orig_addr,1);
}

uint32_t PAnonymizer_deanonymize(const char * key,const uint32_t orig_addr) {
    return PAnonymizer_action(key,orig_addr,0);
}

// https://gist.github.com/bricef/2436364
int encrypt(
    void* buffer,
    int buffer_len, /* Because the plaintext could include null bytes*/
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}
 
  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}
 
int decrypt(
    void* buffer,
    int buffer_len,
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}
