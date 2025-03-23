// [error: wrong use of identifier]
import "tests"

rule c {
    condition:
        tests.string_array == /aab/
}
