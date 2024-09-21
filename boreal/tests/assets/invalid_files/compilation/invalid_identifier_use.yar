// [error: wrong use of identifier]
import "pe"

rule c {
    condition:
        pe.sections == /aab/
}
