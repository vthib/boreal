// [error: invalid identifier type]
import "tests"

rule c {
    condition:
        tests.string_array.foo == /aab/
}
