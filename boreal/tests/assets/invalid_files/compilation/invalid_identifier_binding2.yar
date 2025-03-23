// [error: expected 1 identifiers to bind, got 2]
import "tests"

rule a {
    condition:
        for any k, v in tests.integer_array: (true)
}
