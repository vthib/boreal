// [error: expected an expression of type integer]
import "tests"

rule a {
    condition:
        tests.integer_array["a"] == 3
}
