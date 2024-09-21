// [error: identifier is not iterable]
import "pe"

rule a {
    condition:
        for any a, b in pe.is_dll: (true)
}
