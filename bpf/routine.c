#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <string.h>

#include "routine.h"
#include <sqlite3.h>
#include <assert.h>

Routine* routines[16];

size_t file_len(char* filename){
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    fclose(file);
    return file_size;
}

int read_file(char* filename, char* buffer) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fread(buffer, 1, file_size, file) != file_size) {
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

void routine_init_ubpf_vm(Routine* r) {
    struct ubpf_vm* vm = ubpf_create();
    if (vm == NULL) {
        return;
    }

    r->bpf_map_ctx = NULL; //bpf_map_ctx();

    ubpf_toggle_bounds_check(vm, false);
    ubpf_toggle_undefined_behavior_check(vm, false);
    //ubpf_register_data_relocation(vm, r->bpf_map_ctx, do_map_relocation);
    ubpf_set_jit_code_size(vm, 128*1024); // default is 64KB

    // register bpf helpers
    
    ubpf_register(vm, 1, "internal_insertElement", as_external_function_t((void*) internal_insertElement));
    ubpf_register(vm, 2, "internal_findElementWithHash", as_external_function_t((void*) internal_findElementWithHash));
    ubpf_register(vm, 3, "internal_removeElement", as_external_function_t((void*) internal_removeElement));
    ubpf_register(vm, 4, "internal_rehash", as_external_function_t((void*) internal_rehash));
    ubpf_register(vm, 5, "internal_malloc", as_external_function_t((void*) sqlite3_malloc));
    //ubpf_register(vm, 1, "bpf_map_lookup_elem", as_external_function_t((void *) bpf_map_lookup_elem));
    //ubpf_register(vm, 2, "bpf_map_update_elem", as_external_function_t((void *) bpf_map_update_elem));
    //ubpf_register(vm, 3, "bpf_map_delete_elem", as_external_function_t((void *) bpf_map_delete_elem));
    //ubpf_register(vm, 5, "bpf_ktime_get_ns", as_external_function_t((void *) bpf_ktime_get_ns));
    //ubpf_register(vm, 6, "bpf_trace_printk", as_external_function_t((void *) bpf_trace_printk));
    //ubpf_register(vm, 7, "bpf_get_prandom_u32", as_external_function_t((void *) bpf_get_prandom_u32));
    //ubpf_register(vm, 20, "unwind", as_external_function_t((void *) unwind));
    //ubpf_set_unwind_function_index(vm, 20);
    
    r->ubpf_vm = vm;
}

const char pub_key_str[] = R"(
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK3AvjjQR+NrRqhcadKOqjkUY/OHj
RmAU5ua9+XLW8RomQQtgubMBciF2BRlzGKH6LOAxgt4RwRI6qlhVOEEegg==
-----END PUBLIC KEY-----
)";

int routine_check_bpf_verification_signature(Routine* r) {
    // Create a BIO for the public key
    BIO *bio = BIO_new_mem_buf(pub_key_str, strlen(pub_key_str));
    if (!bio) {
        return printf("Unable to create BIO for public key\n");
    }

    // Read public key from the BIO
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        return printf("Failed to read public key\n");
    }

    // Read the file to be verified
    char* file_contents = (char*)malloc(sizeof(char)*file_len(r->bpf_file));
    read_file(r->bpf_file, file_contents);
    if (strlen(file_contents) == 0) {
        EVP_PKEY_free(pkey);
        return printf("Failed to read file to be verified\n");
    }

    // Read the signature
    char* signature = (char*)malloc(sizeof(char)*file_len(r->signature_file));
    read_file(r->signature_file, signature);
    if (strlen(signature) == 0) {
        EVP_PKEY_free(pkey);
        return printf("Failed to read signature file\n");
    }

    // Compute SHA-256 hash of the file
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!EVP_Digest(file_contents, strlen(file_contents), hash, NULL, EVP_sha256(), NULL)) {
        EVP_PKEY_free(pkey);
        return printf("Failed to compute SHA-256 hash\n");
    }

    // Create context for verification
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return printf("Failed to create EVP_MD_CTX\n");
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return printf("Failed to initialize digest verify context\n");
    }

    // Perform verification
    if (EVP_DigestVerify(mdctx, signature, strlen(signature), hash, SHA256_DIGEST_LENGTH) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return printf("Signature verification failed\n");
    }

    // Clean up
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    uk_pr_info("Signature of BPF bytecode '%s' verified successfully with signature file '%s'\n", r->bpf_file, r->signature_file);
    return 0;
}

int routine_configure(int ID, char* bpf_file, char* signature_file) {
    Routine* r = (Routine*)malloc(sizeof(Routine));
    r->lock = UK_RWLOCK_INITIALIZER(r->lock, 0);
    r->id = ID;
    r->bpf_file = (char*)malloc(strlen(bpf_file) * sizeof(char));
    r->signature_file = (char*)malloc(strlen(signature_file) * sizeof(char));
    strcpy(r->bpf_file, bpf_file);
    strcpy(r->signature_file, signature_file);

    bool reconfigure = r->ubpf_vm != NULL;
    if (reconfigure) {
        uk_pr_info("Reconfiguring ID: %lu with program %s (signature: %s)...\n", r->id, r->bpf_file, r->signature_file);
    } else {
        uk_pr_info("Configuring ID: %lu with program %s (signature: %s)...\n", r->id, r->bpf_file, r->signature_file);
    }

	  uint64_t ts_begin = ukplat_monotonic_clock();
    size_t file_size = file_len(r->bpf_file);
    char* buffer = (char*)malloc(sizeof(char)*file_size);
    int res = read_file(r->bpf_file, buffer);
    if (res < 0) {
        return printf("Error reading file %s\n", r->bpf_file);
    }

    if (!reconfigure) {
       routine_init_ubpf_vm(r);
        if (r->ubpf_vm == NULL) {
            return printf("Error initializing ubpf vm\n");
        }
    }

    uk_rwlock_wlock(&r->lock);
    if (reconfigure) {
        ubpf_unload_code(r->ubpf_vm);
    }

    char *error_msg;
    ubpf_load_elf_ex(r->ubpf_vm, buffer, file_size, "routine_implem", &error_msg);

    if (error_msg != NULL) {
        return printf("Error loading ubpf program: %s\n", error_msg);
    }

#ifdef CONFIG_LIBSQLITE_UBPF_VERIFY_SIGNATURE
    if (CONFIG_LIBCLICK_UBPF_VERIFY_SIGNATURE) {
        int return_code = routine_check_bpf_verification_signature(r);
        if (return_code < 0) {
            return return_code;
        }
    }
#endif

    r->ubpf_jit_fn = ubpf_compile(r->ubpf_vm, &error_msg);
    if (r->ubpf_jit_fn == NULL) {
        return printf("Error compiling ubpf program: %s\n", error_msg);
    }

	  uint64_t ts_end = ukplat_monotonic_clock();
	  printf("Reconfiguration time (nsec): : %lu\n", ts_end - ts_begin);

    uk_rwlock_wunlock(&r->lock);

    if (reconfigure) {
        uk_pr_info("Reconfigured ID: %lu with program %s (signature: %s)...\n", r->id, r->bpf_file, r->signature_file);
    } else {
        uk_pr_info("Configured ID: %lu with program %s (signature: %s)...\n", r->id, r->bpf_file, r->signature_file);
    }
    routines[ID] = r;

    return 0;
}

uint64_t call_routine(int ID, void* p1, void* p2, void* p3){ //, void* p4, void* p5, void* p6) {
    if(routines[ID] == NULL){
        return 0;
    }
    Routine* r = routines[ID];
    arguments ctx = (arguments) {
            .ptr1 = p1,
            .ptr2 = p2,
            .ptr3 = p3,
            /*.ptr4 = p4,
            .ptr5 = p5,
            .ptr6 = p6,*/
    };

    void* ret = (void*)r->ubpf_jit_fn(&ctx, sizeof(ctx));
    return (uint64_t)ret;
}
