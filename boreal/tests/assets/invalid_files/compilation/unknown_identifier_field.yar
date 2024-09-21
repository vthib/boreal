// [error: unknown field "myn"]
import "pe"

rule a {
    condition:
        pe.myn == 2
}
