#include "elf_parser.h"
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

const char* arc_name(uint16_t a) {
    switch (a) {
        case EM_X86_64:  return "x86-64";
        default: "uncnown"
    }
}

static long vaddr_to_offset(int fd, const Elf64_Ehdr* eh, uint64_t vaddr) {
    if (lseek(fd, (off_t)eh->e_phoff, SEEK_SET) == (off_t)-1)
        return -1;

    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr ph;
        ssize_t r = read(fd, &ph, sizeof(ph));
        if (r < (ssize_t)sizeof(ph)) return -1;

        if (ph.p_type != PT_LOAD) continue;

        if (vaddr >= ph.p_vaddr &&
            vaddr <  ph.p_vaddr + ph.p_memsz) {
            return (long)(ph.p_offset + (vaddr - ph.p_vaddr));
        }
    }
    return -1;
}

int elf_parse(const char* path, elf_info_t* info) {
    memset(info, 0, sizeof(*info));

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    unsigned char magic[4];
    ssize_t n = read(fd, magic, 4);
    if (n < 4) { close(fd); return -1; }

    if (magic[0] != 0x7f || magic[1] != 'E' ||
        magic[2] != 'L'  || magic[3] != 'F') {
        close(fd);
        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) { close(fd); return -1; }

    Elf64_Ehdr eh;
    ssize_t m = read(fd, &eh, sizeof(eh));
    if (m < (ssize_t)sizeof(eh)) { close(fd); return -1; }

    info->is_elf    = 1;
    info->is_64bit  = 1;
    info->e_machine = eh.e_machine;
    info->e_type    = eh.e_type;

    if (eh.e_phoff == 0 || eh.e_phnum == 0) { close(fd); return -1; }

    off_t file_end = lseek(fd, 0, SEEK_END);
    if (file_end < 0) { close(fd); return -1; }

    uint64_t table_end = eh.e_phoff + (uint64_t)eh.e_phnum * eh.e_phentsize;
    if ((off_t)table_end > file_end) { close(fd); return -1; }

    if (lseek(fd, (off_t)eh.e_phoff, SEEK_SET) == (off_t)-1) {
        close(fd);
        return -1;
    }

    uint64_t dyn_off     = 0;
    uint64_t dyn_size    = 0;
    int      has_dynamic = 0;

    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        ssize_t r = read(fd, &ph, sizeof(ph));
        if (r < (ssize_t)sizeof(ph)) { close(fd); return -1; }

        if (ph.p_type == PT_INTERP) {
            info->is_executable = 1;
        } else if (ph.p_type == PT_DYNAMIC) {
            has_dynamic = 1;
            dyn_off     = ph.p_offset;
            dyn_size    = ph.p_filesz;
        }
    }

    if (!has_dynamic) {
        info->is_static = 1;
        close(fd);
        return 0;
    }

    if (dyn_off + dyn_size > (uint64_t)file_end) { close(fd); return -1; }

    if (lseek(fd, (off_t)dyn_off, SEEK_SET) == (off_t)-1) {
        close(fd);
        return -1;
    }

    size_t dcount = (size_t)(dyn_size / sizeof(Elf64_Dyn));
    if (dcount == 0) { close(fd); return -1; }

    Elf64_Dyn* dyns = malloc(dcount * sizeof(Elf64_Dyn));
    if (!dyns) { close(fd); return -1; }

    ssize_t dr = read(fd, dyns, dcount * sizeof(Elf64_Dyn));
    if (dr < (ssize_t)(dcount * sizeof(Elf64_Dyn))) {
        free(dyns);
        close(fd);
        return -1;
    }

    uint64_t strtab_addr = 0;
    for (size_t i = 0; i < dcount; i++) {
        if (dyns[i].d_tag == DT_STRTAB) {
            strtab_addr = dyns[i].d_un.d_ptr;
            break;
        }
    }

    if (strtab_addr == 0) {
        free(dyns);
        close(fd);
        return -1;
    }

    long strtab_off = vaddr_to_offset(fd, &eh, strtab_addr);
    if (strtab_off < 0 || (uint64_t)strtab_off >= (uint64_t)file_end) {
        free(dyns);
        close(fd);
        return -1;
    }

    uint64_t strtab_max = (uint64_t)file_end - (uint64_t)strtab_off;

    for (size_t i = 0; i < dcount && info->needed_count < MAX_NEEDED; i++) {
        if (dyns[i].d_tag != DT_NEEDED) continue;

        uint64_t off = dyns[i].d_un.d_val;
        if (off >= strtab_max) continue;

        if (lseek(fd, (off_t)(strtab_off + off), SEEK_SET) == (off_t)-1)
            continue;

        char   name[MAX_LIBNAME];
        size_t k = 0;
        while (k < MAX_LIBNAME - 1) {
            char c;
            ssize_t r = read(fd, &c, 1);
            if (r != 1) break;
            if (c == '\0') break;
            name[k++] = c;
        }
        name[k] = '\0';

        memcpy(info->needed[info->needed_count].name, name, k);
        info->needed[info->needed_count].name[k] = '\0';
        info->needed_count++;
    }

    free(dyns);
    close(fd);
    return 0;
}
