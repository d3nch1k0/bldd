#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int format_from_string(const char* s, report_format_t* out) {
    if      (strcmp(s, "txt")  == 0) *out = FORMAT_TXT;
    else if (strcmp(s, "html") == 0) *out = FORMAT_HTML;
    else if (strcmp(s, "json") == 0) *out = FORMAT_JSON;
    else return -1;
    return 0;
}

const char* format_ext(report_format_t fmt) {
    switch (fmt) {
        case FORMAT_TXT:  return "txt";
        case FORMAT_HTML: return "html";
        case FORMAT_JSON: return "json";
    }
    return "txt";
}

static int cmp_desc(const void* a, const void* b) {
    const exec_entry_t* x = (const exec_entry_t*)a;
    const exec_entry_t* y = (const exec_entry_t*)b;
    if (x->dep_count != y->dep_count) return y->dep_count - x->dep_count;
    return strcmp(x->path, y->path);
}

static void now_string(char* buf, size_t sz) {
    time_t t = time(NULL);
    struct tm* lt = localtime(&t);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", lt);
}

static void json_escape(FILE* f, const char* s) {
    for (; *s; s++) {
        switch (*s) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n",  f); break;
            case '\r': fputs("\\r",  f); break;
            case '\t': fputs("\\t",  f); break;
            default:
                if ((unsigned char)*s < 0x20) fprintf(f, "\\u%04x", *s);
                else                          fputc(*s, f);
        }
    }
}

static void html_escape(FILE* f, const char* s) {
    for (; *s; s++) {
        switch (*s) {
            case '<': fputs("&lt;",   f); break;
            case '>': fputs("&gt;",   f); break;
            case '&': fputs("&amp;",  f); break;
            case '"': fputs("&quot;", f); break;
            default:  fputc(*s, f);
        }
    }
}

typedef struct {
    char name[MAX_LIBNAME];
    int  count;
} lib_count_t;

static lib_count_t* collect_libraries(const exec_list_t* list, int* out_count) {
    if (list->count == 0) { *out_count = 0; return NULL; }
    size_t cap = (size_t)list->count * (size_t)MAX_NEEDED;
    lib_count_t* libs = malloc(cap * sizeof(lib_count_t));
    if (!libs) { *out_count = 0; return NULL; }

    int n = 0;
    for (int i = 0; i < list->count; i++) {
        for (int j = 0; j < list->items[i].needed_count; j++) {
            const char* nm = list->items[i].needed[j];
            int found = 0;
            for (int k = 0; k < n; k++) {
                if (strcmp(libs[k].name, nm) == 0) {
                    libs[k].count++;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                strncpy(libs[n].name, nm, MAX_LIBNAME - 1);
                libs[n].name[MAX_LIBNAME - 1] = '\0';
                libs[n].count = 1;
                n++;
            }
        }
    }
    *out_count = n;
    return libs;
}

static int cmp_lib_desc(const void* a, const void* b) {
    const lib_count_t* x = (const lib_count_t*)a;
    const lib_count_t* y = (const lib_count_t*)b;
    if (x->count != y->count) return y->count - x->count;
    return strcmp(x->name, y->name);
}

static int write_txt(const char* path, const char* ts,
                     const char* scan_dir, const char* lib,
                     const char* arch, const exec_list_t* list)
{
    FILE* f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "BLDD Report\n===========\n");
    fprintf(f, "Generated:       %s\n", ts);
    fprintf(f, "Scan dir:        %s\n", scan_dir);
    fprintf(f, "Target lib:      %s\n", lib);
    fprintf(f, "Target arch:     %s\n", arch);
    fprintf(f, "Files scanned:   %d\n", list->total_files);
    fprintf(f, "ELF files:       %d\n", list->elf_files);
    fprintf(f, "ELF executables: %d\n", list->elf_executables);
    fprintf(f, "Static execs:    %d\n", list->static_executables);
    fprintf(f, "Matches:         %d\n\n", list->count);

    int lib_count = 0;
    lib_count_t* libs = collect_libraries(list, &lib_count);
    if (libs) {
        qsort(libs, (size_t)lib_count, sizeof(lib_count_t), cmp_lib_desc);
        fprintf(f, "Libraries used by matches:\n");
        fprintf(f, "%-40s %s\n", "Library", "Files");
        fprintf(f, "--------------------------------------------------\n");
        for (int i = 0; i < lib_count; i++)
            fprintf(f, "%-40s %d\n", libs[i].name, libs[i].count);
        fprintf(f, "\n");
        free(libs);
    }

    fprintf(f, "Executables (sorted by dependency count, descending):\n");
    fprintf(f, "------------------------------------------------------------\n");
    for (int i = 0; i < list->count; i++) {
        fprintf(f, "%d) %s  [%s, deps=%d]\n",
                i + 1,
                list->items[i].path,
                list->items[i].machine,
                list->items[i].dep_count);
        for (int j = 0; j < list->items[i].needed_count; j++)
            fprintf(f, "     - %s\n", list->items[i].needed[j]);
    }
    fclose(f);
    return 0;
}

static int write_html(const char* path, const char* ts,
                      const char* scan_dir, const char* lib,
                      const char* arch, const exec_list_t* list)
{
    FILE* f = fopen(path, "w");
    if (!f) return -1;

    fputs("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
          "<title>BLDD Report</title>"
          "<style>body{font-family:sans-serif;margin:2em;}"
          "table{border-collapse:collapse;margin-bottom:1.5em;}"
          "th,td{border:1px solid #999;padding:4px 8px;vertical-align:top;}"
          "th{background:#eee;}</style></head><body>\n", f);

    fputs("<h1>BLDD Report</h1>\n<ul>\n", f);
    fprintf(f, "<li><b>Generated:</b> ");   html_escape(f, ts);       fputs("</li>\n", f);
    fprintf(f, "<li><b>Scan dir:</b> ");    html_escape(f, scan_dir); fputs("</li>\n", f);
    fprintf(f, "<li><b>Target lib:</b> ");  html_escape(f, lib);      fputs("</li>\n", f);
    fprintf(f, "<li><b>Target arch:</b> "); html_escape(f, arch);     fputs("</li>\n", f);
    fprintf(f, "<li><b>Files scanned:</b> %d</li>\n", list->total_files);
    fprintf(f, "<li><b>ELF files:</b> %d</li>\n", list->elf_files);
    fprintf(f, "<li><b>ELF executables:</b> %d</li>\n", list->elf_executables);
    fprintf(f, "<li><b>Static executables:</b> %d</li>\n", list->static_executables);
    fprintf(f, "<li><b>Matches:</b> %d</li>\n", list->count);
    fputs("</ul>\n", f);

    int lib_count = 0;
    lib_count_t* libs = collect_libraries(list, &lib_count);
    if (libs) {
        qsort(libs, (size_t)lib_count, sizeof(lib_count_t), cmp_lib_desc);
        fputs("<h2>Libraries used by matches</h2>\n<table>\n"
              "<thead><tr><th>Library</th><th>Files</th></tr></thead>\n<tbody>\n", f);
        for (int i = 0; i < lib_count; i++) {
            fputs("<tr><td>", f); html_escape(f, libs[i].name);
            fprintf(f, "</td><td>%d</td></tr>\n", libs[i].count);
        }
        fputs("</tbody></table>\n", f);
        free(libs);
    }

    fputs("<h2>Executables</h2>\n<table>\n<thead><tr>"
          "<th>#</th><th>Deps</th><th>Arch</th><th>Path</th><th>Needed libs</th>"
          "</tr></thead>\n<tbody>\n", f);
    for (int i = 0; i < list->count; i++) {
        fprintf(f, "<tr><td>%d</td><td>%d</td><td>", i + 1, list->items[i].dep_count);
        html_escape(f, list->items[i].machine);
        fputs("</td><td>", f);
        html_escape(f, list->items[i].path);
        fputs("</td><td>", f);
        for (int j = 0; j < list->items[i].needed_count; j++) {
            html_escape(f, list->items[i].needed[j]);
            if (j + 1 < list->items[i].needed_count) fputs("<br>", f);
        }
        fputs("</td></tr>\n", f);
    }
    fputs("</tbody></table>\n</body></html>\n", f);

    fclose(f);
    return 0;
}

static int write_json(const char* path, const char* ts,
                      const char* scan_dir, const char* lib,
                      const char* arch, const exec_list_t* list)
{
    FILE* f = fopen(path, "w");
    if (!f) return -1;

    fputs("{\n", f);
    fputs("  \"generated\": \"",       f); json_escape(f, ts);       fputs("\",\n", f);
    fputs("  \"scan_dir\": \"",        f); json_escape(f, scan_dir); fputs("\",\n", f);
    fputs("  \"target_library\": \"",  f); json_escape(f, lib);      fputs("\",\n", f);
    fputs("  \"target_arch\": \"",     f); json_escape(f, arch);     fputs("\",\n", f);
    fprintf(f, "  \"files_scanned\": %d,\n",      list->total_files);
    fprintf(f, "  \"elf_files\": %d,\n",          list->elf_files);
    fprintf(f, "  \"elf_executables\": %d,\n",    list->elf_executables);
    fprintf(f, "  \"static_executables\": %d,\n", list->static_executables);
    fprintf(f, "  \"matches\": %d,\n",            list->count);

    int lib_count = 0;
    lib_count_t* libs = collect_libraries(list, &lib_count);
    if (libs) {
        qsort(libs, (size_t)lib_count, sizeof(lib_count_t), cmp_lib_desc);
        fputs("  \"libraries\": [\n", f);
        for (int i = 0; i < lib_count; i++) {
            fputs("    {\"name\": \"", f); json_escape(f, libs[i].name);
            fprintf(f, "\", \"count\": %d}", libs[i].count);
            if (i + 1 < lib_count) fputc(',', f);
            fputc('\n', f);
        }
        fputs("  ],\n", f);
        free(libs);
    } else {
        fputs("  \"libraries\": [],\n", f);
    }

    fputs("  \"executables\": [\n", f);
    for (int i = 0; i < list->count; i++) {
        fputs("    {\"path\": \"", f);  json_escape(f, list->items[i].path);
        fputs("\", \"arch\": \"", f);   json_escape(f, list->items[i].machine);
        fprintf(f, "\", \"deps\": %d, \"needed\": [", list->items[i].dep_count);
        for (int j = 0; j < list->items[i].needed_count; j++) {
            fputc('"', f);
            json_escape(f, list->items[i].needed[j]);
            fputc('"', f);
            if (j + 1 < list->items[i].needed_count) fputc(',', f);
        }
        fputs("]}", f);
        if (i + 1 < list->count) fputc(',', f);
        fputc('\n', f);
    }
    fputs("  ]\n}\n", f);

    fclose(f);
    return 0;
}

int report_generate(const char* out_path,
                    report_format_t fmt,
                    const char* scan_dir,
                    const char* target_lib,
                    const char* target_arch_name,
                    const exec_list_t* list)
{
    exec_list_t copy = *list;
    copy.items = malloc(sizeof(exec_entry_t) * (size_t)list->count);
    if (!copy.items && list->count > 0) return -1;
    memcpy(copy.items, list->items,
           sizeof(exec_entry_t) * (size_t)list->count);
    qsort(copy.items, (size_t)copy.count, sizeof(exec_entry_t), cmp_desc);

    char ts[64];
    now_string(ts, sizeof(ts));

    int rc;
    switch (fmt) {
        case FORMAT_TXT:  rc = write_txt (out_path, ts, scan_dir, target_lib, target_arch_name, &copy); break;
        case FORMAT_HTML: rc = write_html(out_path, ts, scan_dir, target_lib, target_arch_name, &copy); break;
        case FORMAT_JSON: rc = write_json(out_path, ts, scan_dir, target_lib, target_arch_name, &copy); break;
        default:          rc = -1;
    }
    free(copy.items);
    return rc;
}
