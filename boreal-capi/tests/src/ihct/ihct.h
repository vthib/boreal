#ifndef IHCT_H
#define IHCT_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Datatype representing a vector. to be used internally in IHCT_RUN
typedef struct {
    void **data;
    size_t size;
} ihct_vector;

// Allocates a new vector with capacity cap.
ihct_vector *ihct_vector_init();

// Add a pointer to a allocated object at the end of the vector.
void ihct_vector_add(ihct_vector *v, void *obj);

// Gets the object at location index in vector v.
void *ihct_vector_get(ihct_vector *v, int index);

// Deallocates the vector.
void ihct_vector_free(ihct_vector *v);

// Structure for a testunits return value. Contains state, the code (assert) which
// failed the test, and a reference to where the code is.
typedef struct {
    enum {PASS, FAIL, FAIL_FORCE, ERR, TIMEOUT} status;
    char *code;
    char *file;
    unsigned long line;
} ihct_test_result;

// Short for a function returning a test_result pointer, with no arguments.
typedef void (*ihct_test_proc)(ihct_test_result *);

// Called within a test. 
bool ihct_assert_impl(bool eval, ihct_test_result *result, char *code, char *file, 
                      unsigned long line);

void ihct_pass_impl(ihct_test_result *result, char *file, unsigned long line);
void ihct_fail_impl(ihct_test_result *result, char *file, unsigned long line);

// Called on test unit construction.
void ihct_construct_test_impl(char *s, ihct_test_proc proc);

// Runs all tests.
int ihct_run(int argc, char **argv);

// Initializes the unitlist (Has to be done before all testing units are created).
// Using priority to ensure that the unit list is constructed before it gets populated.
void ihct_init(void) __attribute__((constructor(101)));

// Assertions
/// @defgroup assertions Assertions
/// @brief Wraps all assertions.
///
/// Decides the success of a test. Right now, tests can only result in
/// PASS or FAIL. Assertions are only given for expressions.

/// @brief Asserts a statement inside a test unit. If the expression is false,
/// the unit will fail the test.
/// @ingroup assertions
/// @param expr the expression to evaluate.
///
/// Can be shortened to remove 'IHCT_' prefix by defining IHCT_SHORT.
#define IHCT_ASSERT(expr)                                                               \
    if(!ihct_assert_impl(expr, result, #expr, __FILE__, __LINE__)) return

/// @brief Asserts a statement inside a test unit. If the expression is true,
/// the unit will fail the test.
/// @ingroup assertions
/// @param expr the expression to evaluate.
///
/// Can be shortened to remove 'IHCT_' prefix by defining IHCT_SHORT.
#define IHCT_NASSERT(expr)                                                              \
    if(!ihct_assert_impl(!expr, result, "!(" #expr ")", __FILE__, __LINE__)) return

#define IHCT_ASSERT_EQ(e1, e2)                                                          \
    if(!ihct_assert_impl(e1 == e2, result, #e1 " == " #e2, __FILE__, __LINE__)) return

/// @brief Asserts two strings inside a test unit to be equal. If there is any difference
/// in the strings, the unit will fail the test.
/// @ingroup assertions
/// @param s1 first string to compare
/// @param s2 second string to compare
///
/// Can be shortened to remove 'IHCT_' prefix by defining IHCT_SHORT.
#define IHCT_ASSERT_STR(s1, s2)                                                         \
    if(!ihct_assert_impl(!strcmp(s1, s2), result, #s1 " == " #s2, __FILE__,             \
       __LINE__)) return
/// @brief Asserts two strings inside a test unit not to be equal. If there is any 
/// difference in the strings, the unit will fail the test.
/// @ingroup assertions
/// @param s1 first string to compare
/// @param s2 second string to compare
///
/// Can be shortened to remove 'IHCT_' prefix by defining IHCT_SHORT.
#define IHCT_NASSERT_STR(s1, s2)                                                        \
    if(!ihct_assert_impl(strcmp(s1, s2), result, #s1 " != " #s2, __FILE__,              \
       __LINE__)) return

// Function macros
/// @defgroup funcs Testing functions
/// @brief More general macros for function.

/// @brief Runs all tests. Is to be called once in the main entrypoint.
/// @ingroup funcs
/// @code
/// int main(int argc, char **argv) {
///     return IHCT_RUN(argc, argv);
/// }
/// @endcode
/// @param argc argument count, directly passed from main.
/// @param argv argument array, directly passed from main.
#define IHCT_RUN(argc, argv)                                                            \
    ihct_run(argc, argv)

// Create a new test unit, and adds it using 'ihct_add_test'.
/// @brief Create a new test unit, which can take any number of asserts.
/// @ingroup funcs
/// @code
/// IHCT_TEST(basic_test) {
///     IHCT_ASSERT(1 == 1);
/// }
/// @endcode
/// @param name the name of the test.
///
/// Can be shortened to remove 'IHCT_' prefix by defining IHCT_SHORT.
#define IHCT_TEST(name)                                                                 \
    static void test_##name(ihct_test_result *result);                                  \
    static void __attribute__((constructor(102))) __construct_test_##name(void) {       \
        ihct_construct_test_impl(#name, &test_##name);                                  \
    }                                                                                   \
    static void test_##name(ihct_test_result *result)

/// @brief Defines a fixture with data to be preloaded before a test.
/// A ficture is included by a IHCT_REQUIRE inside a test.
#define IHCT_FIXTURE(name) _Static_assert(0, "Fixtures not implemented.")

/// @brief Make the test require the given fixtures.
/// @param ... one or more fixture names.
#define IHCT_REQUIRE(...) _Static_assert(0, "Fixture requirements not implemented.")

#ifdef IHCT_SHORT
#define TEST(name) IHCT_TEST(name)
#define ASSERT(expr) IHCT_ASSERT(expr)
#define NASSERT(expr) IHCT_NASSERT(expr)
#define ASSERT_STR(s1, s2) IHCT_ASSERT_STR(s1, s2)
#define NASSERT_STR(s1, s2) IHCT_NASSERT_STR(s1, s2)
#define PASS() IHCT_PASS()
#define FAIL() IHCT_FAIL()
#endif

#endif
