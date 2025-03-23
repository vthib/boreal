// [error: identifier is not iterable]
import "math"

rule a {
    condition:
        for any a, b in math.mean: (true)
}
