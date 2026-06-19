#ifndef BOREAL_YARA_H
#define BOREAL_YARA_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Platform-specific file descriptor type */
#ifdef _WIN32
#include <windows.h>
typedef HANDLE YR_FILE_DESCRIPTOR;
#else
typedef int YR_FILE_DESCRIPTOR;
#endif

/* YARA version constants */
#define YR_MAJOR_VERSION 4
#define YR_MINOR_VERSION 5
#define YR_MICRO_VERSION 5

/* Error codes */
#define ERROR_SUCCESS                        0
#define ERROR_INSUFICIENT_MEMORY             1
#define ERROR_INSUFFICIENT_MEMORY            1
#define ERROR_COULD_NOT_ATTACH_TO_PROCESS    2
#define ERROR_COULD_NOT_OPEN_FILE            3
#define ERROR_COULD_NOT_MAP_FILE             4
#define ERROR_INVALID_FILE                   6
#define ERROR_CORRUPT_FILE                   7
#define ERROR_UNSUPPORTED_FILE_VERSION       8
#define ERROR_INVALID_REGULAR_EXPRESSION     9
#define ERROR_INVALID_HEX_STRING             10
#define ERROR_SYNTAX_ERROR                   11
#define ERROR_LOOP_NESTING_LIMIT_EXCEEDED    12
#define ERROR_DUPLICATED_LOOP_IDENTIFIER     13
#define ERROR_DUPLICATED_IDENTIFIER          14
#define ERROR_DUPLICATED_TAG_IDENTIFIER      15
#define ERROR_DUPLICATED_META_IDENTIFIER     16
#define ERROR_DUPLICATED_STRING_IDENTIFIER   17
#define ERROR_UNREFERENCED_STRING            18
#define ERROR_UNDEFINED_STRING               19
#define ERROR_UNDEFINED_IDENTIFIER           20
#define ERROR_MISPLACED_ANONYMOUS_STRING     21
#define ERROR_INCLUDES_CIRCULAR_REFERENCE    22
#define ERROR_INCLUDE_DEPTH_EXCEEDED         23
#define ERROR_WRONG_TYPE                     24
#define ERROR_EXEC_STACK_OVERFLOW            25
#define ERROR_SCAN_TIMEOUT                   26
#define ERROR_TOO_MANY_SCAN_THREADS          27
#define ERROR_CALLBACK_ERROR                 28
#define ERROR_INVALID_ARGUMENT               29
#define ERROR_TOO_MANY_MATCHES               30
#define ERROR_INTERNAL_FATAL_ERROR           31
#define ERROR_NESTED_FOR_OF_LOOP             32
#define ERROR_INVALID_FIELD_NAME             33
#define ERROR_UNKNOWN_MODULE                 34
#define ERROR_NOT_A_STRUCTURE                35
#define ERROR_NOT_INDEXABLE                  36
#define ERROR_NOT_A_FUNCTION                 37
#define ERROR_INVALID_FORMAT                 38
#define ERROR_TOO_MANY_ARGUMENTS             39
#define ERROR_WRONG_ARGUMENTS                40
#define ERROR_WRONG_RETURN_TYPE              41
#define ERROR_DUPLICATED_STRUCTURE_MEMBER    42
#define ERROR_EMPTY_STRING                   43
#define ERROR_DIVISION_BY_ZERO               44
#define ERROR_REGULAR_EXPRESSION_TOO_LARGE   45
#define ERROR_TOO_MANY_RE_FIBERS             46
#define ERROR_COULD_NOT_READ_PROCESS_MEMORY  47
#define ERROR_INVALID_EXTERNAL_VARIABLE_TYPE 48
#define ERROR_REGEXP_TOO_LONG                49
#define ERROR_TOO_MANY_STRINGS               50
#define ERROR_TOO_LONG_CUCKOO_RULE           51
#define ERROR_UNSUPPORTED                    65

/* Scan flags */
#define SCAN_FLAGS_FAST_MODE                 1
#define SCAN_FLAGS_PROCESS_MEMORY            2
#define SCAN_FLAGS_NO_TRYCATCH               4
#define SCAN_FLAGS_REPORT_RULES_MATCHING     8
#define SCAN_FLAGS_REPORT_RULES_NOT_MATCHING 16

/* Callback message types */
#define CALLBACK_MSG_RULE_MATCHING           1
#define CALLBACK_MSG_RULE_NOT_MATCHING       2
#define CALLBACK_MSG_SCAN_FINISHED           3
#define CALLBACK_MSG_IMPORT_MODULE           4
#define CALLBACK_MSG_MODULE_IMPORTED         5
#define CALLBACK_MSG_TOO_MANY_MATCHES        6
#define CALLBACK_MSG_CONSOLE_LOG             7
#define CALLBACK_MSG_TOO_SLOW_SCANNING       8

/* Callback return values */
#define CALLBACK_CONTINUE                    0
#define CALLBACK_ABORT                       1
#define CALLBACK_ERROR                       2

/* Configuration keys */
typedef enum {
    YR_CONFIG_STACK_SIZE,
    YR_CONFIG_MAX_STRINGS_PER_RULE,
    YR_CONFIG_MAX_MATCH_DATA,
    YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK,
    YR_CONFIG_LAST
} YR_CONFIG_NAME;

/* Opaque types */
typedef struct YR_COMPILER YR_COMPILER;
typedef struct YR_RULES YR_RULES;
typedef struct YR_SCANNER YR_SCANNER;
typedef struct YR_RULE YR_RULE;
typedef struct YR_STRING YR_STRING;
typedef struct YR_META YR_META;
typedef struct YR_MATCH YR_MATCH;

/* The scan context passed to callbacks is the scanner object */
typedef YR_SCANNER YR_SCAN_CONTEXT;

/* Stream for serialization */
typedef struct {
    void* user_data;
    size_t (*read)(void* ptr, size_t size, size_t count, void* user_data);
    size_t (*write)(const void* ptr, size_t size, size_t count, void* user_data);
} YR_STREAM;

/* Memory block for fragmented scanning */
typedef struct YR_MEMORY_BLOCK_S YR_MEMORY_BLOCK;
typedef const uint8_t* (*YR_MEMORY_BLOCK_FETCH_DATA_FUNC)(YR_MEMORY_BLOCK* self);

struct YR_MEMORY_BLOCK_S {
    size_t size;
    uint64_t base;
    void* context;
    YR_MEMORY_BLOCK_FETCH_DATA_FUNC fetch_data;
};

typedef struct YR_MEMORY_BLOCK_ITERATOR_S YR_MEMORY_BLOCK_ITERATOR;
typedef YR_MEMORY_BLOCK* (*YR_MEMORY_BLOCK_ITERATOR_FUNC)(YR_MEMORY_BLOCK_ITERATOR* self);
typedef uint64_t (*YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC)(YR_MEMORY_BLOCK_ITERATOR* self);

struct YR_MEMORY_BLOCK_ITERATOR_S {
    void* context;
    YR_MEMORY_BLOCK_ITERATOR_FUNC first;
    YR_MEMORY_BLOCK_ITERATOR_FUNC next;
    YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC file_size;
    int last_error;
};

/* Callback function pointer types */
typedef int (*YR_CALLBACK_FUNC)(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data);

typedef const char* (*YR_COMPILER_INCLUDE_CALLBACK_FUNC)(
    const char* include_name,
    const char* calling_rule_filename,
    const char* calling_rule_namespace,
    void* user_data);

typedef void (*YR_COMPILER_INCLUDE_FREE_FUNC)(
    const char* callback_result_ptr,
    void* user_data);

typedef void (*YR_COMPILER_CALLBACK_FUNC)(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data);

/* Global initialization */
int yr_initialize(void);
int yr_finalize(void);

/* Global configuration */
int yr_set_configuration(YR_CONFIG_NAME name, void* src);
int yr_set_configuration_uint32(YR_CONFIG_NAME name, uint32_t value);
int yr_set_configuration_uint64(YR_CONFIG_NAME name, uint64_t value);
int yr_get_configuration(YR_CONFIG_NAME name, void* dest);
int yr_get_configuration_uint32(YR_CONFIG_NAME name, uint32_t* dest);
int yr_get_configuration_uint64(YR_CONFIG_NAME name, uint64_t* dest);

/* Compiler API */
int yr_compiler_create(YR_COMPILER** compiler);
void yr_compiler_destroy(YR_COMPILER* compiler);
void yr_compiler_set_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_CALLBACK_FUNC callback,
    void* user_data);
void yr_compiler_set_include_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_INCLUDE_CALLBACK_FUNC callback,
    YR_COMPILER_INCLUDE_FREE_FUNC free_callback,
    void* user_data);
int yr_compiler_add_string(
    YR_COMPILER* compiler,
    const char* rules_string,
    const char* namespace_);
int yr_compiler_add_bytes(
    YR_COMPILER* compiler,
    const void* rules_data,
    size_t rules_size,
    const char* namespace_);
int yr_compiler_add_file(
    YR_COMPILER* compiler,
    FILE* rules_file,
    const char* namespace_,
    const char* file_name);
int yr_compiler_add_fd(
    YR_COMPILER* compiler,
    YR_FILE_DESCRIPTOR rules_fd,
    const char* namespace_,
    const char* file_name);
char* yr_compiler_get_error_message(
    YR_COMPILER* compiler,
    char* buffer,
    int buffer_size);
char* yr_compiler_get_current_file_name(YR_COMPILER* compiler);
int yr_compiler_define_integer_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int64_t value);
int yr_compiler_define_boolean_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int value);
int yr_compiler_define_float_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    double value);
int yr_compiler_define_string_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    const char* value);
int yr_compiler_get_rules(YR_COMPILER* compiler, YR_RULES** rules);

/* Rule enable/disable */
void yr_rule_disable(YR_RULE* rule);
void yr_rule_enable(YR_RULE* rule);

/* Rules API */
int yr_rules_destroy(YR_RULES* rules);
int yr_rules_define_integer_variable(
    YR_RULES* rules,
    const char* identifier,
    int64_t value);
int yr_rules_define_boolean_variable(
    YR_RULES* rules,
    const char* identifier,
    int value);
int yr_rules_define_float_variable(
    YR_RULES* rules,
    const char* identifier,
    double value);
int yr_rules_define_string_variable(
    YR_RULES* rules,
    const char* identifier,
    const char* value);
int yr_rules_scan_mem(
    YR_RULES* rules,
    const uint8_t* buffer,
    size_t buffer_size,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);
int yr_rules_scan_mem_blocks(
    YR_RULES* rules,
    YR_MEMORY_BLOCK_ITERATOR* iterator,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);
int yr_rules_scan_file(
    YR_RULES* rules,
    const char* filename,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);
int yr_rules_scan_fd(
    YR_RULES* rules,
    YR_FILE_DESCRIPTOR fd,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);
int yr_rules_scan_proc(
    YR_RULES* rules,
    int pid,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);
int yr_rules_save(YR_RULES* rules, const char* filename);
int yr_rules_load(const char* filename, YR_RULES** rules);
int yr_rules_save_stream(YR_RULES* rules, YR_STREAM* stream);
int yr_rules_load_stream(YR_STREAM* stream, YR_RULES** rules);

/* Scanner API */
int yr_scanner_create(YR_RULES* rules, YR_SCANNER** scanner);
void yr_scanner_destroy(YR_SCANNER* scanner);
void yr_scanner_set_callback(
    YR_SCANNER* scanner,
    YR_CALLBACK_FUNC callback,
    void* user_data);
void yr_scanner_set_timeout(YR_SCANNER* scanner, int timeout);
void yr_scanner_set_flags(YR_SCANNER* scanner, int flags);
int yr_scanner_define_integer_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    int64_t value);
int yr_scanner_define_boolean_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    int value);
int yr_scanner_define_float_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    double value);
int yr_scanner_define_string_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    const char* value);
int yr_scanner_scan_mem(
    YR_SCANNER* scanner,
    const uint8_t* buffer,
    size_t buffer_size);
int yr_scanner_scan_mem_blocks(
    YR_SCANNER* scanner,
    YR_MEMORY_BLOCK_ITERATOR* iterator);
int yr_scanner_scan_file(YR_SCANNER* scanner, const char* filename);
int yr_scanner_scan_fd(YR_SCANNER* scanner, YR_FILE_DESCRIPTOR fd);
int yr_scanner_scan_proc(YR_SCANNER* scanner, int pid);
YR_RULE* yr_scanner_last_error_rule(YR_SCANNER* scanner);
YR_STRING* yr_scanner_last_error_string(YR_SCANNER* scanner);

#ifdef __cplusplus
}
#endif

#endif /* BOREAL_YARA_H */
