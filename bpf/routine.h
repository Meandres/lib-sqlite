#ifndef ROUTINE_H
#define ROUTINE_H

#include <stdint.h>
#include <uk/rwlock.h>
//#include <bpf_helpers.hh>
#include <ubpf.h>

typedef struct {
    struct uk_rwlock lock;
    struct ubpf_vm *ubpf_vm;
    uint64_t id;
    char* bpf_file;
    char* signature_file;

    struct bpf_map_ctx *bpf_map_ctx;
    ubpf_jit_fn ubpf_jit_fn;
} Routine;

extern Routine* routines[16];

typedef struct {
    void* ptr1;
    void* ptr2;
    void* ptr3;
    /*void* ptr4;
    void* ptr5;
    void* ptr6;*/
} arguments;

void routine_init(Routine* r);

int routine_configure(int ID, char* bpf_file, char* signature_file);
uint64_t call_routine(int ID, void* ptr1, void* ptr2, void* ptr3); //, void* ptr4, void* ptr5, void* ptr6);

void routine_init_ubpf_vm(Routine* r);
int routine_check_bpf_verification_signature(Routine* r);

#endif
