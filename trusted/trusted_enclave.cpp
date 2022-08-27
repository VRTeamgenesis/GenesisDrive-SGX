#include "sgx_tcrypto.h"
#include "tSgxSSL_api.h"
#include "sgx_thread.h"
#include "sgx_attributes.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_error.h"

#include "enclave_t.h"

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include <cstring>

#define RSA4096BIT_KEY_LEN 4096
#define RSA2048BIT_KEY_LEN 2048
#define RSA1024BIT_KEY_LEN 1024


sgx_status_t seal_bytes(uint8_t* bytes, size_t size, sgx_sealed_data_t** sealed_bytes, size_t* sealed_size) {
      sgx_attributes_t attributes = { 0xfffffffffffffff3, 0 };
  *sealed_size = sgx_calc_sealed_data_size(NULL, size);

  if(*sealed_size > 0 && *sealed_size < 0xffffffff) { 

    *sealed_bytes = (sgx_sealed_data_t*)malloc(*sealed_size);
    
    return sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE,
              attributes,
              0,
              NULL,
              NULL, 
              size,
              bytes,
              (uint32_t)*sealed_size, 
              *sealed_bytes);        
  }
}

sgx_status_t unseal_bytes(sgx_sealed_data_t* sealed_bytes, uint8_t** plain_bytes) {

  size_t plain_data_size  = sgx_get_encrypt_txt_len(sealed_bytes);

  if (plain_data_size != 0 && plain_data_size < 0xffffffff) {
    *plain_bytes = (uint8_t*)malloc(plain_data_size);

    return sgx_unseal_data(sealed_bytes,
              NULL, 
              NULL, 
              (*plain_bytes), 
              (uint32_t*)&plain_data_size);
    

  } 
}

void write_file(char* filename,uint8_t* content,size_t size){
    SGX_FILE* fp = sgx_fopen_auto_key(filename, "w+");
    if (fp == NULL){ 
        ocall_print("Invalid");
    }
    size_t count = sgx_fwrite(content,1,size,fp);
    sgx_fflush(fp);
    sgx_fclose(fp);
}

size_t read_file(char* filename, uint8_t** content){
    SGX_FILE* fp = sgx_fopen_auto_key(filename, "r+");
    uint64_t startN = 1;
    sgx_fseek(fp, 0, SEEK_END);
    uint64_t size = sgx_ftell(fp);
    sgx_fseek(fp, 0, SEEK_SET);
    *content = (uint8_t*) malloc(size);
    return sgx_fread(*content, startN, size, fp);
}


void getkey(uint8_t* id,size_t len,uint8_t* passphrase, size_t passlen) {
  
  sgx_sealed_data_t * keybytes = NULL;
  int readbytes = read_file("key.enc",(uint8_t**)&keybytes);

  uint8_t* key = NULL;

  if( readbytes ) {
    sgx_status_t t = unseal_bytes(keybytes,&key);
  } else {
    key = (uint8_t*)malloc(32);

    sgx_status_t s;
    s = sgx_read_rand(key,32);
    
    sgx_sealed_data_t * sealed_key = NULL;
    size_t sealed_key_size ;
    sgx_status_t t = seal_bytes(key,32,&sealed_key,&sealed_key_size);

    write_file("key.enc",(uint8_t*)sealed_key,sealed_key_size);
  }

  uint8_t source[64];

  memcpy(source,id,32);
  memcpy(source+32,key,32);

  sgx_sha256_hash_t p_hash;
  sgx_status_t ret = sgx_sha256_msg(source,64,&p_hash);

  memcpy(passphrase,p_hash,32);
}