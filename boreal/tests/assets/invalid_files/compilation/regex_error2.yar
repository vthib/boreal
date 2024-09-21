// [error: regex failed to build: Error("Compiled regex exceeds size limit of 10485760 bytes.")]
rule a {
    condition:
        /.{1,999999}/
}
