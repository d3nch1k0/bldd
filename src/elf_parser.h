#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <stdint.h>

#define MAX_NEEDED 256
#define MAX_LIBNAME 256

typedef struct{
    char name[MAX_LIBNAME];
}needed_entry_t;

typedef struct{
    int is_elf;
    int is_executable;
    int is_static;
    int is_64bit;
    uint16_t  e_machine;
    uint16_t  e_type; 
    needed_entry_t needed[MAX_NEEDED];
    int needed_count;
    
}elf_info_t;

int elf_parse(const char* path, elf_info_t* info);

const char* arc_name(uint16_t e_machine);

#endif
