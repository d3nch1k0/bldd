#include "elf_parser.h"
#include "scanner.h"
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_help(const char* prog) {
    printf(
"bldd\n"
"\n"
"Находит все исполняемые ELF-файлы в каталоге, которые зависят от указанной\n"
"разделяемой библиотеки, и формирует отчёт (txt / html / json).\n"
"\n"
"Использование:\n"
"  %s -l <lib> -d <dir> -f txt|html|json\n"
"\n"
"  -l <lib>   имя или путь разделяемой библиотеки\n"
"  -d <dir>   каталог для рекурсивного сканирования\n"
"  -f <fmt>   формат отчёта: txt (по умолчанию), html, json\n"
"  -h         показать эту справку\n",
        prog);
}

static int find_library_arch(const char* libname, uint16_t* out_arch) {
    static const char* dirs[] = {
        "/lib", "/usr/lib",
        "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
        NULL
    };

    if (strchr(libname, '/')) {
        elf_info_t info;
        if (elf_parse(libname, &info) == 0 && info.is_elf) {
            *out_arch = info.e_machine;
            return 0;
        }
        return -1;
    }

    char path[4096];
    for (int i = 0; dirs[i]; i++) {
        int n = snprintf(path, sizeof(path), "%s/%s", dirs[i], libname);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        elf_info_t info;
        if (elf_parse(path, &info) == 0 && info.is_elf) {
            *out_arch = info.e_machine;
            return 0;
        }
    }
    return -1;
}

int main(int argc, char** argv) {
    const char* lib     = NULL;
    const char* dir     = NULL;
    const char* fmt_str = "txt";

    int opt;
    while ((opt = getopt(argc, argv, "l:d:f:h")) != -1) {
        switch (opt) {
            case 'l': lib     = optarg; break;
            case 'd': dir     = optarg; break;
            case 'f': fmt_str = optarg; break;
            case 'h': print_help(argv[0]); return 0;
            default:  print_help(argv[0]); return 1;
        }
    }

    if (!lib || !dir) {
        fprintf(stderr, "Error: -l and -d are required\n\n");
        print_help(argv[0]);
        return 1;
    }

    report_format_t fmt;
    if (format_from_string(fmt_str, &fmt) != 0) {
        fprintf(stderr, "Error: unknown format '%s' (use txt|html|json)\n", fmt_str);
        return 1;
    }

    char outfile[256];
    snprintf(outfile, sizeof(outfile), "bldd_report.%s", format_ext(fmt));

    uint16_t target_arch = 0;
    int      has_arch    = (find_library_arch(lib, &target_arch) == 0);
    const char* arch_str = has_arch ? arc_name(target_arch) : "unknown";

    exec_list_t list;
    exec_list_init(&list);

    if (scan_directory(dir, lib, target_arch, has_arch, &list, 0) != 0) {
        fprintf(stderr, "Error: cannot scan directory '%s'\n", dir);
        exec_list_free(&list);
        return 1;
    }

    if (report_generate(outfile, fmt, dir, lib, arch_str, &list) != 0) {
        fprintf(stderr, "Error: cannot write report '%s'\n", outfile);
        exec_list_free(&list);
        return 1;
    }

    printf("Report written: %s\n", outfile);
    printf("  scanned files:      %d\n", list.total_files);
    printf("  ELF files:          %d\n", list.elf_files);
    printf("  ELF executables:    %d\n", list.elf_executables);
    printf("  static executables: %d\n", list.static_executables);
    printf("  matches:            %d\n", list.count);

    exec_list_free(&list);
    return 0;
}
