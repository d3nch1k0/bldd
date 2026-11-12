#include "scanner.h"
#include "elf_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

void exec_list_init(exec_list_t* list) {
    memset(list, 0, sizeof(*list));
}

void exec_list_free(exec_list_t* list) {
    free(list->items);
    list->items = NULL;
    list->count = list->cap = 0;
}

static void exec_list_add(exec_list_t* list, const exec_entry_t* e) {
    if (list->count >= list->cap) {
        int newcap = list->cap ? list->cap * 2 : 16;
        exec_entry_t* tmp = realloc(list->items,
                                    (size_t)newcap * sizeof(exec_entry_t));
        if (!tmp) return;
        list->items = tmp;
        list->cap   = newcap;
    }
    list->items[list->count++] = *e;
}

static void strip_version(const char* name, char* out, size_t outsz) {
    size_t len = strlen(name);
    if (len >= outsz) len = outsz - 1;
    memcpy(out, name, len);
    out[len] = '\0';

    char* dot = strrchr(out, '.');
    if (!dot || dot == out) return;

    int all_digits = 1;
    for (char* p = dot + 1; *p; p++) {
        if (!isdigit((unsigned char)*p)) { all_digits = 0; break; }
    }
    if (all_digits) *dot = '\0';
}

static int lib_matches(const char* target, const char* needed) {
    if (strcmp(target, needed) == 0) return 1;

    char a[MAX_LIBNAME], b[MAX_LIBNAME];
    strip_version(target, a, sizeof(a));
    strip_version(needed, b, sizeof(b));
    return strcmp(a, b) == 0;
}

typedef struct {
    const char*  target_lib;
    uint16_t     target_arch;
    int          has_target_arch;
    exec_list_t* out;
    int          verbose;
} scan_ctx_t;

static void process_file(const char* path, scan_ctx_t* ctx) {
    elf_info_t info;
    if (elf_parse(path, &info) != 0) return;
    ctx->out->elf_files++;

    if (!info.is_executable) {
        if (info.is_static) {
            ctx->out->static_executables++;
            if (ctx->verbose)
                fprintf(stderr, "[i] static executable: %s (%s)\n",
                        path, arc_name(info.e_machine));
        }
        return;
    }
    ctx->out->elf_executables++;

    int matches = 0;
    for (int i = 0; i < info.needed_count; i++) {
        if (lib_matches(ctx->target_lib, info.needed[i].name)) {
            matches = 1;
            break;
        }
    }
    if (!matches) return;

    if (ctx->has_target_arch && info.e_machine != ctx->target_arch) {
        if (ctx->verbose)
            fprintf(stderr, "[!] arch mismatch: %s (%s != %s)\n",
                    path, arc_name(info.e_machine),
                    arc_name(ctx->target_arch));
        return;
    }

    exec_entry_t e;
    memset(&e, 0, sizeof(e));
    strncpy(e.path, path, sizeof(e.path) - 1);
    strncpy(e.machine, arc_name(info.e_machine), sizeof(e.machine) - 1);
    e.e_machine = info.e_machine;
    e.dep_count = info.needed_count;

    exec_list_add(ctx->out, &e);

    if (ctx->verbose)
        fprintf(stderr, "[+] %s (%s, deps=%d)\n",
                path, e.machine, e.dep_count);
}

static void walk_dir(const char* dir, scan_ctx_t* ctx) {
    DIR* d = opendir(dir);
    if (!d) {
        if (ctx->verbose) fprintf(stderr, "[!] cannot open: %s\n", dir);
        return;
    }

    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 ||
            strcmp(ent->d_name, "..") == 0) continue;

        char path[4096];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;

        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;

        if (S_ISDIR(st.st_mode)) {
            walk_dir(path, ctx);
        } else if (S_ISREG(st.st_mode)) {
            ctx->out->total_files++;
            if (access(path, R_OK) != 0) {
                if (ctx->verbose)
                    fprintf(stderr, "[!] no read access: %s\n", path);
                continue;
            }
            process_file(path, ctx);
        }
    }
    closedir(d);
}

int scan_directory(const char* dir,
                   const char* target_lib,
                   uint16_t    target_arch,
                   int         has_target_arch,
                   exec_list_t* out,
                   int         verbose)
{
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) return -1;

    scan_ctx_t ctx = { target_lib, target_arch,
                       has_target_arch, out, verbose };
    walk_dir(dir, &ctx);
    return 0;
}
