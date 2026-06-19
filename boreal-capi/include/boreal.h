#ifndef INCLUDE_BOREAL_H
# define INCLUDE_BOREAL_H

// For FILE
#include <stdio.h>

// For (u)intX_t types
#include <stdint.h>


#if defined(_WIN32)
#include <windows.h>
# define YR_FILE_DESCRIPTOR HANDLE
#else
# define YR_FILE_DESCRIPTOR int
#endif


typedef struct _YR_RULE YR_RULE;
typedef struct _YR_RULES YR_RULES;
typedef struct _YR_COMPILER YR_COMPILER;

int yr_compiler_create(YR_COMPILER** compiler);

void yr_compiler_destroy(YR_COMPILER* compiler);

/*
typedef void (*YR_COMPILER_CALLBACK_FUNC)(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data);

void yr_compiler_set_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_CALLBACK_FUNC callback,
    void* user_data);
*/

/*
typedef const char* (*YR_COMPILER_INCLUDE_CALLBACK_FUNC)(
    const char* include_name,
    const char* calling_rule_filename,
    const char* calling_rule_namespace,
    void* user_data);

typedef void (*YR_COMPILER_INCLUDE_FREE_FUNC)(
    const char* callback_result_ptr,
    void* user_data);

void yr_compiler_set_include_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_INCLUDE_CALLBACK_FUNC include_callback,
    YR_COMPILER_INCLUDE_FREE_FUNC include_free,
    void* user_data);
*/

/*
void yr_compiler_set_atom_quality_table(
    YR_COMPILER* compiler,
    const void* table,
    int entries,
    unsigned char warning_threshold);

int yr_compiler_load_atom_quality_table(
    YR_COMPILER* compiler,
    const char* filename,
    unsigned char warning_threshold);
*/

/*
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
*/

int yr_compiler_add_bytes(
    YR_COMPILER* compiler,
    const void* rules_data,
    size_t rules_size,
    const char* namespace_);

int yr_compiler_add_string(
    YR_COMPILER* compiler,
    const char* rules_string,
    const char* namespace_);

/*
char* yr_compiler_get_error_message(
    YR_COMPILER* compiler,
    char* buffer,
    int buffer_size);
    */

// TODO

/*
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
*/

int yr_compiler_get_rules(YR_COMPILER* compiler, YR_RULES** rules);

/* libyara.h */

// TODO

/*
#define YR_MAJOR_VERSION 4
#define YR_MINOR_VERSION 5
#define YR_MICRO_VERSION 5

#define YR_VERSION                               \
  version_str(YR_MAJOR_VERSION) "." version_str( \
      YR_MINOR_VERSION) "." version_str(YR_MICRO_VERSION)

// Version as a single 4-byte hex number, e.g. 0x030401 == 3.4.1.
#define YR_VERSION_HEX \
  ((YR_MAJOR_VERSION << 16) | (YR_MINOR_VERSION << 8) | (YR_MICRO_VERSION << 0))
*/

int yr_initialize(void);

int yr_finalize(void);

// TODO

/*
// Enumerated type listing configuration options
typedef enum _YR_CONFIG_NAME
{
  YR_CONFIG_STACK_SIZE,
  YR_CONFIG_MAX_STRINGS_PER_RULE,
  YR_CONFIG_MAX_MATCH_DATA,
  YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK,

  YR_CONFIG_LAST  // End-of-enum marker, not a configuration

} YR_CONFIG_NAME;

int yr_set_configuration(YR_CONFIG_NAME, void*);
int yr_set_configuration_uint32(YR_CONFIG_NAME, uint32_t);
int yr_set_configuration_uint64(YR_CONFIG_NAME, uint64_t);

int yr_get_configuration(YR_CONFIG_NAME, void*);
int yr_get_configuration_uint32(YR_CONFIG_NAME, uint32_t*);
int yr_get_configuration_uint64(YR_CONFIG_NAME, uint64_t*);
*/

/* modules.h */

// TODO: to keep?

/*
typedef struct YR_MODULE
{
  char* name;

  // TODO?
  void *declarations;
  void *load;
  void *unload;
  void *initialize;
  void *finalize;
} YR_MODULE;

YR_MODULE* yr_modules_get_table(void);
*/

/* rules.h */

#define CALLBACK_MSG_RULE_MATCHING     1
#define CALLBACK_MSG_RULE_NOT_MATCHING 2
#define CALLBACK_MSG_SCAN_FINISHED     3
#define CALLBACK_MSG_IMPORT_MODULE     4
#define CALLBACK_MSG_MODULE_IMPORTED   5
#define CALLBACK_MSG_TOO_MANY_MATCHES  6
#define CALLBACK_MSG_CONSOLE_LOG       7
#define CALLBACK_MSG_TOO_SLOW_SCANNING 8

#define CALLBACK_CONTINUE 0
#define CALLBACK_ABORT    1
#define CALLBACK_ERROR    2

/*

#define yr_rule_tags_foreach(rule, tag_name)                         \
  for (tag_name = rule->tags; tag_name != NULL && *tag_name != '\0'; \
       tag_name += strlen(tag_name) + 1)

#define yr_rule_metas_foreach(rule, meta) \
  for (meta = rule->metas; meta != NULL;  \
       meta = META_IS_LAST_IN_RULE(meta) ? NULL : meta + 1)

#define yr_rule_strings_foreach(rule, string)  \
  for (string = rule->strings; string != NULL; \
       string = STRING_IS_LAST_IN_RULE(string) ? NULL : string + 1)

#define yr_string_matches_foreach(context, string, match)         \
  for (match = context->matches[string->idx].head; match != NULL; \
       match = match->next)                                       \
    if (match->is_private)                                        \
    {                                                             \
      continue;                                                   \
    }                                                             \
    else

#define yr_rules_foreach(rules, rule) \
  for (rule = rules->rules_table; !RULE_IS_NULL(rule); rule++)

int yr_rules_scan_mem_blocks(
    YR_RULES* rules,
    YR_MEMORY_BLOCK_ITERATOR* iterator,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);

int yr_rules_scan_mem(
    YR_RULES* rules,
    const uint8_t* buffer,
    size_t buffer_size,
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

int yr_rules_save_stream(YR_RULES* rules, YR_STREAM* stream);

int yr_rules_load(const char* filename, YR_RULES** rules);

int yr_rules_load_stream(YR_STREAM* stream, YR_RULES** rules);
*/

int yr_rules_destroy(YR_RULES* rules);

/*
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

int yr_rules_get_stats(YR_RULES* rules, YR_RULES_STATS* stats);

void yr_rule_disable(YR_RULE* rule);

void yr_rule_enable(YR_RULE* rule);
*/

/* scanner.h */

typedef struct _YR_SCANNER YR_SCANNER;

typedef struct YR_SCAN_CONTEXT
{
  // TODO: what to keep in here?

  // File size of the file being scanned.
  uint64_t file_size;

  // Entry point of the file being scanned, if the file is PE or ELF.
  uint64_t entry_point;
} YR_SCAN_CONTEXT;

typedef int (*YR_CALLBACK_FUNC)(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data);

int yr_scanner_create(YR_RULES* rules, YR_SCANNER** scanner);

void yr_scanner_destroy(YR_SCANNER* scanner);

void yr_scanner_set_callback(
    YR_SCANNER* scanner,
    YR_CALLBACK_FUNC callback,
    void* user_data);

// TODO
// void yr_scanner_set_timeout(YR_SCANNER* scanner, int timeout);
// 
// void yr_scanner_set_flags(YR_SCANNER* scanner, int flags);
// 
// int yr_scanner_define_integer_variable(
//     YR_SCANNER* scanner,
//     const char* identifier,
//     int64_t value);
// 
// int yr_scanner_define_boolean_variable(
//     YR_SCANNER* scanner,
//     const char* identifier,
//     int value);
// 
// int yr_scanner_define_float_variable(
//     YR_SCANNER* scanner,
//     const char* identifier,
//     double value);
// 
// int yr_scanner_define_string_variable(
//     YR_SCANNER* scanner,
//     const char* identifier,
//     const char* value);

// TODO: yara_scan_mem_blocks

/*
typedef struct YR_MEMORY_BLOCK YR_MEMORY_BLOCK;
typedef struct YR_MEMORY_BLOCK_ITERATOR YR_MEMORY_BLOCK_ITERATOR;

typedef const uint8_t* (*YR_MEMORY_BLOCK_FETCH_DATA_FUNC)(
    YR_MEMORY_BLOCK* self);

struct YR_MEMORY_BLOCK
{
  size_t size;
  uint64_t base;

  void* context;

  YR_MEMORY_BLOCK_FETCH_DATA_FUNC fetch_data;
};

const uint8_t* yr_fetch_block_data(YR_MEMORY_BLOCK* self);

typedef YR_MEMORY_BLOCK* (*YR_MEMORY_BLOCK_ITERATOR_FUNC)(
    YR_MEMORY_BLOCK_ITERATOR* self);

typedef uint64_t (*YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC)(
    YR_MEMORY_BLOCK_ITERATOR* self);

struct YR_MEMORY_BLOCK_ITERATOR
{
  // A pointer that can be used by specific implementations of an iterator for
  // storing the iterator's state.
  void* context;

  // Pointers to functions for iterating over the memory blocks.
  YR_MEMORY_BLOCK_ITERATOR_FUNC first;
  YR_MEMORY_BLOCK_ITERATOR_FUNC next;

  // Pointer to a function that returns the file size as computed by the
  // iterator. This is a the size returned by the filesize keyword in YARA
  // rules. If this pointer is NULL the file size will be undefined.
  YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC file_size;

  // Error occurred during the last call to "first" or "next" functions. These
  // functions must set the value of last_error to ERROR_SUCCESS or to some
  // other error code if appropriate. Alternatively, last_error can be set to
  // ERROR_SUCCESS before using the iterator and changed by "first" or "next"
  // only when they want to report an error.
  int last_error;
};

int yr_scanner_scan_mem_blocks(
    YR_SCANNER* scanner,
    YR_MEMORY_BLOCK_ITERATOR* iterator);
*/

int yr_scanner_scan_mem(
    YR_SCANNER* scanner,
    const uint8_t* buffer,
    size_t buffer_size);

// int yr_scanner_scan_file(YR_SCANNER* scanner, const char* filename);
// 
// int yr_scanner_scan_fd(YR_SCANNER* scanner, YR_FILE_DESCRIPTOR fd);
// 
// int yr_scanner_scan_proc(YR_SCANNER* scanner, int pid);

// TODO?
// YR_RULE* yr_scanner_last_error_rule(YR_SCANNER* scanner);

// TODO: yr_scanner_last_error_string: to keep?

/*
typedef struct YR_STRING
{
  // Flags, see STRING_FLAGS_XXX macros defined above.
  uint32_t flags;

  // Index of this string in the array of YR_STRING structures stored in
  // YR_STRINGS_TABLE.
  uint32_t idx;

  // If the string can only match at a specific offset (for example if the
  // condition is "$a at 0" the string $a can only match at offset 0), the
  // fixed_offset field contains the offset, it have the YR_UNDEFINED value for
  // strings that can match anywhere.
  int64_t fixed_offset;

  // Index of the rule containing this string in the array of YR_RULE
  // structures stored in YR_RULES_TABLE.
  uint32_t rule_idx;

  // String's length.
  int32_t length;

  // Pointer to the string itself, the length is indicated by the "length"
  // field.
  uint8_t *string;

  // Identifier of this string.
  const char*identifier;
} YR_STRING;

YR_STRING* yr_scanner_last_error_string(YR_SCANNER* scanner);
*/

// TODO: Profiling info: to keep ?

/*
typedef struct YR_RULE_PROFILING_INFO
{
  YR_RULE* rule;
  uint64_t cost;
} YR_RULE_PROFILING_INFO;

YR_RULE_PROFILING_INFO* yr_scanner_get_profiling_info(
    YR_SCANNER* scanner);

void yr_scanner_reset_profiling_info(YR_SCANNER* scanner);

int yr_scanner_print_profiling_info(YR_SCANNER* scanner);
*/

#endif /* INCLUDE_BOREAL_H */
