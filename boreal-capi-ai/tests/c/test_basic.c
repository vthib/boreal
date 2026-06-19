#include "yara.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ---- helpers ---- */

typedef struct {
    int match_count;
    int finished;
} ScanState;

static int scan_callback(YR_SCAN_CONTEXT* ctx, int message, void* data, void* user_data) {
    (void)ctx;
    (void)data;
    ScanState* state = (ScanState*)user_data;
    if (message == CALLBACK_MSG_RULE_MATCHING)
        state->match_count++;
    if (message == CALLBACK_MSG_SCAN_FINISHED)
        state->finished = 1;
    return CALLBACK_CONTINUE;
}

static YR_RULES* compile_rules(const char* source) {
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    assert(yr_compiler_create(&compiler) == ERROR_SUCCESS);
    assert(yr_compiler_add_string(compiler, source, NULL) == ERROR_SUCCESS);
    assert(yr_compiler_get_rules(compiler, &rules) == ERROR_SUCCESS);
    yr_compiler_destroy(compiler);
    return rules;
}

/* ---- individual tests ---- */

static void test_initialize_finalize(void) {
    assert(yr_initialize() == ERROR_SUCCESS);
    assert(yr_finalize() == ERROR_SUCCESS);
    printf("PASS: test_initialize_finalize\n");
}

static void test_compiler_create_destroy(void) {
    yr_initialize();
    YR_COMPILER* compiler = NULL;
    assert(yr_compiler_create(&compiler) == ERROR_SUCCESS);
    assert(compiler != NULL);
    yr_compiler_destroy(compiler);
    yr_finalize();
    printf("PASS: test_compiler_create_destroy\n");
}

static void test_compiler_add_string_error(void) {
    yr_initialize();
    YR_COMPILER* compiler = NULL;
    assert(yr_compiler_create(&compiler) == ERROR_SUCCESS);
    int ret = yr_compiler_add_string(compiler, "not valid yara", NULL);
    assert(ret != ERROR_SUCCESS);
    char buf[256];
    yr_compiler_get_error_message(compiler, buf, sizeof(buf));
    assert(strlen(buf) > 0);
    yr_compiler_destroy(compiler);
    yr_finalize();
    printf("PASS: test_compiler_add_string_error\n");
}

static void test_rules_scan_mem_match(void) {
    yr_initialize();
    YR_RULES* rules = compile_rules(
        "rule test { strings: $a = \"hello\" condition: $a }");

    ScanState state = {0, 0};
    const uint8_t mem[] = "say hello world";
    int ret = yr_rules_scan_mem(
        rules, mem, sizeof(mem) - 1, 0, scan_callback, &state, 0);
    assert(ret == ERROR_SUCCESS);
    assert(state.match_count == 1);
    assert(state.finished == 1);

    yr_rules_destroy(rules);
    yr_finalize();
    printf("PASS: test_rules_scan_mem_match\n");
}

static void test_rules_scan_mem_no_match(void) {
    yr_initialize();
    YR_RULES* rules = compile_rules(
        "rule test { strings: $a = \"hello\" condition: $a }");

    ScanState state = {0, 0};
    const uint8_t mem[] = "goodbye world";
    int ret = yr_rules_scan_mem(
        rules, mem, sizeof(mem) - 1, 0, scan_callback, &state, 0);
    assert(ret == ERROR_SUCCESS);
    assert(state.match_count == 0);
    assert(state.finished == 1);

    yr_rules_destroy(rules);
    yr_finalize();
    printf("PASS: test_rules_scan_mem_no_match\n");
}

static void test_scanner_create_destroy(void) {
    yr_initialize();
    YR_RULES* rules = compile_rules("rule test { condition: true }");

    YR_SCANNER* scanner = NULL;
    assert(yr_scanner_create(rules, &scanner) == ERROR_SUCCESS);
    assert(scanner != NULL);
    yr_scanner_destroy(scanner);
    yr_rules_destroy(rules);
    yr_finalize();
    printf("PASS: test_scanner_create_destroy\n");
}

static void test_scanner_scan_mem(void) {
    yr_initialize();
    YR_RULES* rules = compile_rules(
        "rule test { strings: $a = \"hello\" condition: $a }");

    YR_SCANNER* scanner = NULL;
    assert(yr_scanner_create(rules, &scanner) == ERROR_SUCCESS);

    ScanState state = {0, 0};
    yr_scanner_set_callback(scanner, scan_callback, &state);

    const uint8_t mem[] = "say hello world";
    int ret = yr_scanner_scan_mem(scanner, mem, sizeof(mem) - 1);
    assert(ret == ERROR_SUCCESS);
    assert(state.match_count == 1);
    assert(state.finished == 1);

    yr_scanner_destroy(scanner);
    yr_rules_destroy(rules);
    yr_finalize();
    printf("PASS: test_scanner_scan_mem\n");
}

static void test_scanner_multiple_scans(void) {
    yr_initialize();
    YR_RULES* rules = compile_rules(
        "rule test { strings: $a = \"hello\" condition: $a }");

    YR_SCANNER* scanner = NULL;
    assert(yr_scanner_create(rules, &scanner) == ERROR_SUCCESS);

    ScanState s1 = {0, 0};
    yr_scanner_set_callback(scanner, scan_callback, &s1);
    assert(yr_scanner_scan_mem(scanner, (const uint8_t*)"hello", 5) == ERROR_SUCCESS);
    assert(s1.match_count == 1);

    ScanState s2 = {0, 0};
    yr_scanner_set_callback(scanner, scan_callback, &s2);
    assert(yr_scanner_scan_mem(scanner, (const uint8_t*)"world", 5) == ERROR_SUCCESS);
    assert(s2.match_count == 0);

    yr_scanner_destroy(scanner);
    yr_rules_destroy(rules);
    yr_finalize();
    printf("PASS: test_scanner_multiple_scans\n");
}

static void test_external_variable(void) {
    yr_initialize();
    YR_COMPILER* compiler = NULL;
    assert(yr_compiler_create(&compiler) == ERROR_SUCCESS);
    assert(yr_compiler_define_boolean_variable(compiler, "my_var", 0) == ERROR_SUCCESS);
    assert(yr_compiler_add_string(compiler,
        "rule test { condition: my_var }", NULL) == ERROR_SUCCESS);
    YR_RULES* rules = NULL;
    assert(yr_compiler_get_rules(compiler, &rules) == ERROR_SUCCESS);
    yr_compiler_destroy(compiler);

    ScanState s1 = {0, 0};
    assert(yr_rules_define_boolean_variable(rules, "my_var", 0) == ERROR_SUCCESS);
    assert(yr_rules_scan_mem(rules, (const uint8_t*)"x", 1, 0, scan_callback, &s1, 0) == ERROR_SUCCESS);
    assert(s1.match_count == 0);

    ScanState s2 = {0, 0};
    assert(yr_rules_define_boolean_variable(rules, "my_var", 1) == ERROR_SUCCESS);
    assert(yr_rules_scan_mem(rules, (const uint8_t*)"x", 1, 0, scan_callback, &s2, 0) == ERROR_SUCCESS);
    assert(s2.match_count == 1);

    yr_rules_destroy(rules);
    yr_finalize();
    printf("PASS: test_external_variable\n");
}

static void test_configuration(void) {
    yr_initialize();
    uint32_t val = 0;
    assert(yr_set_configuration_uint32(YR_CONFIG_MAX_MATCH_DATA, 256) == ERROR_SUCCESS);
    assert(yr_get_configuration_uint32(YR_CONFIG_MAX_MATCH_DATA, &val) == ERROR_SUCCESS);
    assert(val == 256);
    yr_set_configuration_uint32(YR_CONFIG_MAX_MATCH_DATA, 512);
    yr_finalize();
    printf("PASS: test_configuration\n");
}

static void test_null_arguments(void) {
    assert(yr_compiler_create(NULL) == ERROR_INVALID_ARGUMENT);
    assert(yr_compiler_add_string(NULL, "rule r{condition:true}", NULL) == ERROR_INVALID_ARGUMENT);
    assert(yr_rules_destroy(NULL) == ERROR_SUCCESS);
    assert(yr_scanner_create(NULL, NULL) == ERROR_INVALID_ARGUMENT);
    printf("PASS: test_null_arguments\n");
}

int main(void) {
    test_initialize_finalize();
    test_compiler_create_destroy();
    test_compiler_add_string_error();
    test_rules_scan_mem_match();
    test_rules_scan_mem_no_match();
    test_scanner_create_destroy();
    test_scanner_scan_mem();
    test_scanner_multiple_scans();
    test_external_variable();
    test_configuration();
    test_null_arguments();
    printf("All C API tests passed.\n");
    return 0;
}
