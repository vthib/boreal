import "pe"

rule c {
    condition:
        pe() == /aab/
}
