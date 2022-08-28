#include <stdio.h>

#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_trts.h"
#include "sgx_urts.h"

#include "enclave_u.h"

#include <time.h>

#include <jni.h>
#include "com_gd_JNI.h"

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "trusted_enclave_signed.so"

sgx_enclave_id_t global_eid = 0;

int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("%d",ret);
        return -1;
    }

    return 0;
}



/*
int SGX_CDECL main(int argc, char *argv[]) {

  
    return 0;
}
*/

JNIEXPORT jbyteArray JNICALL Java_com_gd_JNI_getPassphrase(JNIEnv * env, jobject obj , jstring str) {
    if(global_eid==0)
    initialize_enclave();
    ocall_print( (char*)env->GetStringUTFChars(str,nullptr) );
    const char *id = env->GetStringUTFChars(str, nullptr);
    ocall_print_bytes("id",(unsigned char*)id,env->GetStringLength(str));
    uint8_t passphrase [32];
    sgx_status_t t = getkey(global_eid,(uint8_t*)id,env->GetStringLength(str),passphrase,32);
    //t = getkey(global_eid,(uint8_t*)id,env->GetStringLength(str),passphrase,32);

    ocall_print_key_value("status",t);
    ocall_print_bytes("pass",passphrase,32);
    jbyte* buf = new jbyte[32];
  	memcpy (buf, passphrase, 32);
  	jbyteArray ret = env->NewByteArray(32);
  	env->SetByteArrayRegion (ret, 0, 32, buf);
  	return ret;
  }


//Ocalls 

void ocall_print_bytes(char* name,unsigned char* b,size_t len) {
  printf("%s \n",name);
  for(int i =0;i<len;i++) {
    printf("%02x",b[i]);
  }
  printf("\n");
}

void ocall_print( char* str ) {
  printf("Print :: %s\n",str);
}

void ocall_print_key_value(char* key, int value) {
  printf("%s :: %d\n",key,value);
}