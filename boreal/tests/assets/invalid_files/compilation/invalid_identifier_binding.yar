// [error: expected 2 identifiers to bind, got 1]
import "tests"

rule a {
    condition:
        for any a in tests.integer_dict: (true)
}
