#include <boreal.h>
#include <ihct.h>

struct scan_result {
    unsigned int nb_rules_matches;
};

int scan_callback(YR_SCAN_CONTEXT *context, int message, void *message_data, void *user_data) {
    (void)context;
    (void)message_data;
    struct scan_result *result = user_data;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        result->nb_rules_matches += 1;
    }

    return CALLBACK_CONTINUE;
}

IHCT_TEST(basic_scan) {
    YR_COMPILER *compiler;
    int res;

    res = yr_compiler_create(&compiler);
    IHCT_ASSERT_EQ(res, 0);

    res = yr_compiler_add_string(compiler,
"rule a { \
    strings: \
        $ = \"abc\" \
        $ = /<\\d>/ \
    condition: \
        all of them \
}", NULL);
    IHCT_ASSERT_EQ(res, 0);

    YR_RULES *rules;
    res = yr_compiler_get_rules(compiler, &rules);
    IHCT_ASSERT_EQ(res, 0);

    YR_SCANNER *scanner;
    res = yr_scanner_create(rules, &scanner);
    IHCT_ASSERT_EQ(res, 0);

    struct scan_result results = {0};
    yr_scanner_set_callback(scanner, scan_callback, &results);

    const char *data = "dcabc <3>";
    res = yr_scanner_scan_mem(scanner, (const uint8_t *)data, strlen(data));
    IHCT_ASSERT_EQ(res, 0);

    IHCT_ASSERT_EQ(results.nb_rules_matches, 0);

    yr_scanner_destroy(scanner);
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
}

int main(int argc, char **argv) {
    yr_initialize();
    int res = IHCT_RUN(argc, argv);
    yr_finalize();

    return res;
}
