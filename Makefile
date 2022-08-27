######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_SSL ?= /opt/intel/sgxssl
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0

JAVA_HOME ?= /usr/lib/jvm/java-8-openjdk-amd64/

OUTPUT := out

UAPP_NAME := $(OUTPUT)/libgdrive.so
TAPP_NAME := $(OUTPUT)/trusted_enclave.so

SGXSSL_INCLUDE_PATH := $(SGX_SSL)/include
SGXSSL_LIBRARY_PATH := $(SGX_SSL)/lib64

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_FLAGS += -O0 -g
	SGXSSL_Untrusted_Library_Name := sgx_usgxssld
	SGXSSL_Trusted_Library_Name := sgx_tsgxssld
	OpenSSL_Crypto_Library_Name := sgx_tsgxssl_cryptod
else
    SGX_COMMON_FLAGS += -O2
	SGXSSL_Untrusted_Library_Name := sgx_usgxssl
	SGXSSL_Trusted_Library_Name := sgx_tsgxssl
	OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Enclave_Config_File := conf/trusted_enclave_config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


Untrusted_Cpp_Files :=  $(shell find untrusted -name '*.cpp')
Untrusted_Include_Paths :=-I$(SGX_SDK)/include -Iuntrusted/include -Itrusted/include -Icommon -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux
Untrusted_C_Flags := -fPIC -Wno-attributes $(Untrusted_Include_Paths)


ifeq ($(SGX_DEBUG), 1)
        Untrusted_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Untrusted_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Untrusted_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Untrusted_Cpp_Flags := $(Untrusted_C_Flags) -std=c++11
Untrusted_Link_Flags := -L/usr/local/lib  -L$(SGX_LIBRARY_PATH) -L$(SGXSSL_LIBRARY_PATH) -l$(Urts_Library_Name) -lsgx_ukey_exchange -lpthread  -l$(SGXSSL_Untrusted_Library_Name) -lssl -lcrypto -lsgx_uprotected_fs

ifneq ($(SGX_MODE), HW)
	Untrusted_Link_Flags += -lsgx_uae_service_sim
else
	Untrusted_Link_Flags += -lsgx_uae_service
endif

Untrusted_Cpp_Objects := $(Untrusted_Cpp_Files:.cpp=.o)

untrusted/include/enclave_u.h: $(SGX_EDGER8R) edl/enclave.edl
	@cd untrusted && $(SGX_EDGER8R) --untrusted ../edl/enclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include/
	@mv untrusted/enclave_u.h untrusted/include/
	@echo "GEN  =>  $@"

untrusted/enclave_u.c: untrusted/include/enclave_u.h

untrusted/enclave_u.o: untrusted/enclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Untrusted_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(UAPP_NAME): untrusted/enclave_u.o 
	@echo $@ $(Untrusted_Link_Flags) $(Untrusted_Cpp_Objects)
	@$(CXX) untrusted/enclave_u.o $(SGX_COMMON_CXXFLAGS) $(Untrusted_Cpp_Flags) $(Untrusted_Link_Flags) -lpthread $(Untrusted_Cpp_Files) -lcrypto -shared -o $@ 
	@echo "LINK =>  $@"

Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(shell find trusted -name '*.cpp')
Enclave_Include_Paths := -Itrusted -Itrusted/include -Icommon -I$(SGX_SSL)/include/ -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx
Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_C_Flags += -fstack-protector
else
	Enclave_C_Flags += -fstack-protector-strong
endif

Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++


SgxSSL_Link_Libraries := -L$(SGXSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Trusted_Library_Name) -Wl,--no-whole-archive \
						 -l$(OpenSSL_Crypto_Library_Name) -Wl,--whole-archive -lsgx_pthread

Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

Enclave_Link_Flags := $(Enclave_Security_Link_Flags) \
	$(SgxSSL_Link_Libraries) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tkey_exchange -lsgx_tstdc -lsgx_tcxx -lsgx_tprotected_fs -lsgx_tcrypto -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=trusted/enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Trusted_Enclave_Hash := $(OUTPUT)/enclave_hash.hex

Signed_Enclave_Name := $(OUTPUT)/trusted_enclave_signed.so
# Enclave_Config_File := conf/trusted_enclave_config.xml


trusted/include/enclave_t.h: $(SGX_EDGER8R) edl/enclave.edl
	@cd trusted && $(SGX_EDGER8R) --trusted ../edl/enclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include/
	@mv trusted/enclave_t.h trusted/include
	@echo "GEN  =>  $@"

trusted/enclave_t.c: trusted/include/enclave_t.h

trusted/enclave_t.o: trusted/enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

trusted/%.o: trusted/%.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@ 
	@echo "CXX  <=  $<"

$(TAPP_NAME): trusted/enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o  $@ $(Enclave_Link_Flags) 
	@$(SGX_ENCLAVE_SIGNER) gendata -enclave $(TAPP_NAME) -config $(Enclave_Config_File) -out $(Trusted_Enclave_Hash)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name) : $(TAPP_NAME)
	@$(SGX_ENCLAVE_SIGNER) sign -key key/rsa-3072-private-key.pem -enclave $(TAPP_NAME) -out $@ -config $(Enclave_Config_File)


.PHONY: all target clean

all: target

ifeq ($(Build_Mode), HW_RELEASE)
target:	.config_$(Build_Mode)_$(SGX_ARCH) $(UAPP_NAME) $(Signed_Enclave_Name)
	@echo "building in HW mode"
else
target: .config_$(Build_Mode)_$(SGX_ARCH) $(UAPP_NAME) $(Signed_Enclave_Name)
	@echo "building in non HW mode"
endif

clean:
	@rm -f untrusted/*.o untrusted/*.c untrusted/include/enclave_u.h 
	@rm -f trusted/*.o trusted/*.c trusted/include/enclave_t.h  
	@rm -f $(OUTPUT)/*.hex $(OUTPUT)/*.so $(OUTPUT)/gdrive .config_*

.config_$(Build_Mode)_$(SGX_ARCH):
	@touch .config_$(Build_Mode)_$(SGX_ARCH)
	@mkdir -p $(OUTPUT)
	@mkdir -p trusted/include
	@mkdir -p untrusted/include