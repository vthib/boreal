// [error: invalid identifier type]
import "tests"

rule c {
    condition:
        tests.struct_array() == /aab/
}
