#ifndef REPORT_H
#define REPORT_H

#include "scanner.h"

typedef enum {
    FORMAT_TXT,
    FORMAT_HTML,
    FORMAT_JSON
} report_format_t;

int  format_from_string(const char* s, report_format_t* out);
const char* format_ext(report_format_t fmt);

int report_generate(const char* out_path,
                    report_format_t fmt,
                    const char* scan_dir,
                    const char* target_lib,
                    const char* target_arch_name,
                    const exec_list_t* list);

#endif
