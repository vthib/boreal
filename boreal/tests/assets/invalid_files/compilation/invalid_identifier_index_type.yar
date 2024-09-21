// [error: expected an expression of type integer]
import "pe"

rule a {
    condition:
        pe.sections["a"] == 3
}
