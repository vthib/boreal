// [error: invalid arguments types: [integer]]
import "pe"

rule a {
    condition:
        pe.is_dll(2) == 3
}
