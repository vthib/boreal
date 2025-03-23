// [error: wrong use of identifier]
import "tests"

rule c {
    condition:
        for any a in tests.empty_struct_array: (
            a.struct_array == 2
        )
}
