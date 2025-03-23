// [error: wrong use of identifier]
import "time"

rule c {
    condition:
        time == 2
}

