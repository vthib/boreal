// [error: expected 1 identifiers to bind, got 3]
import "pe"

rule a {
    condition:
        for any k, v, t in (0, 1, 2): (true)
}
