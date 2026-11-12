#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include "elf_parser.h"

typedef struct {
    char     path[4096];
    char     machine[64];
    uint16_t e_machine;
    int      dep_count;
    int      needed_count;
    char     needed[MAX_NEEDED][MAX_LIBNAME];
} exec_entry_t;

typedef struct {
    exec_entry_t* items;
    int count;
    int cap;
    int total_files;
    int elf_files;
    int elf_executables;
    int static_executables;
} exec_list_t;

void exec_list_init(exec_list_t* list);
void exec_list_free(exec_list_t* list);

int scan_directory(const char* dir,
                   const char* target_lib,
                   uint16_t    target_arch,
                   int         has_target_arch,
                   exec_list_t* out,
                   int         verbose);

#endif
