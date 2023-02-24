use crate::libyara_compat::util::TEXT_1024_BYTES;
use crate::utils::check;

fn make_rule(cond: &str) -> String {
    format!(
        r#"
import "hash"

rule test {{
    condition: {cond}
}}"#
    )
}

#[track_caller]
fn test(cond: &str, input: &[u8]) {
    check(&make_rule(cond), input, true);
}

#[test]
fn test_md5() {
    test(
        r#"hash.md5(0, filesize) == "0cc175b9c0f1b6a831c399e269772661""#,
        b"a",
    );
    test(
        r#"hash.md5(0, filesize) == "dcc824971a00e589619ba0c0bba41515""#,
        TEXT_1024_BYTES.as_bytes(),
    );
    test(
        r#"hash.md5(50, 100) == "5c026f2a09609f79c46a7dab7398d4ac""#,
        TEXT_1024_BYTES.as_bytes(),
    );

    test(
        r#"hash.md5("abcdefghijklmnopqrstuvwxyz") == "c3fcd3d76192e4007dfb496cca67e13b""#,
        b"",
    );
    test(
        r#"hash.md5(0, filesize) == "c3fcd3d76192e4007dfb496cca67e13b""#,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.md5(0, filesize * 2) == hash.md5(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.md5(0, filesize)"#, b"");
    test(r#"not defined hash.md5(5, filesize)"#, b"a");
    test(r#"not defined hash.md5(-1, filesize)"#, b"a");
    test(r#"not defined hash.md5(0, -1)"#, b"a");
}

#[test]
fn test_sha1() {
    test(
        r#"hash.sha1(0, filesize) == "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8""#,
        b"a",
    );
    test(
        r#"hash.sha1(0, filesize) == "ccb665bf4d6e19b56d3f70e9cc2837dfe3f3a745""#,
        TEXT_1024_BYTES.as_bytes(),
    );
    test(
        r#"hash.sha1(50, 100) == "1d17cf1bd2c85210e088796fe302d08beb27dd5a""#,
        TEXT_1024_BYTES.as_bytes(),
    );

    test(
        r#"hash.sha1("abcdefghijklmnopqrstuvwxyz") == "32d10c7b8cf96570ca04ce37f2a19d84240d3a89""#,
        b"",
    );
    test(
        r#"hash.sha1(0, filesize) == "32d10c7b8cf96570ca04ce37f2a19d84240d3a89""#,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.sha1(0, filesize * 2) == hash.sha1(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.sha1(0, filesize)"#, b"");
    test(r#"not defined hash.sha1(5, filesize)"#, b"a");
    test(r#"not defined hash.sha1(-1, filesize)"#, b"a");
    test(r#"not defined hash.sha1(0, -1)"#, b"a");
}

#[test]
fn test_sha256() {
    test(
        "hash.sha256(0, filesize) == \
            \"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\"",
        b"a",
    );
    test(
        "hash.sha256(0, filesize) == \
            \"62b33f9e7880055a0cb2f195e296f5c5f88043e08d5521199d1ae4f16df7b17b\"",
        TEXT_1024_BYTES.as_bytes(),
    );
    test(
        "hash.sha256(50, 100) == \
            \"a8b65993e5cda9e8c6a93b8913062ae503df81cdebe0af070fd5ec3de4cf7dbf\"",
        TEXT_1024_BYTES.as_bytes(),
    );

    test(
        "hash.sha256(\"abcdefghijklmnopqrstuvwxyz\") == \
            \"71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73\"",
        b"",
    );
    test(
        "hash.sha256(0, filesize) == \
            \"71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73\"",
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.sha256(0, filesize * 2) == hash.sha256(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.sha256(0, filesize)"#, b"");
    test(r#"not defined hash.sha256(5, filesize)"#, b"a");
    test(r#"not defined hash.sha256(-1, filesize)"#, b"a");
    test(r#"not defined hash.sha256(0, -1)"#, b"a");
}

#[test]
fn test_checksum32() {
    test("hash.checksum32(0, filesize) == 97", b"a");
    test(
        "hash.checksum32(0, filesize) == 52946",
        TEXT_1024_BYTES.as_bytes(),
    );
    test(
        "hash.checksum32(50, 100) == 5215",
        TEXT_1024_BYTES.as_bytes(),
    );

    test(
        "hash.checksum32(\"abcdefghijklmnopqrstuvwxyz\") == 2847",
        b"",
    );
    test(
        "hash.checksum32(0, filesize) == 2847",
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.checksum32(0, filesize * 2) == hash.checksum32(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.checksum32(0, filesize)"#, b"");
    test(r#"not defined hash.checksum32(5, filesize)"#, b"a");
    test(r#"not defined hash.checksum32(-1, filesize)"#, b"a");
    test(r#"not defined hash.checksum32(0, -1)"#, b"a");
}

#[test]
fn test_crc32() {
    test("hash.crc32(0, filesize) == 0xe8b7be43", b"a");
    test(
        "hash.crc32(0, filesize) == 0x74cb171",
        TEXT_1024_BYTES.as_bytes(),
    );
    test(
        "hash.crc32(50, 100) == 0x25c34eec",
        TEXT_1024_BYTES.as_bytes(),
    );

    test(
        "hash.crc32(\"abcdefghijklmnopqrstuvwxyz\") == 0x4c2750bd",
        b"",
    );
    test(
        "hash.crc32(0, filesize) == 0x4c2750bd",
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.crc32(0, filesize * 2) == hash.crc32(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.crc32(0, filesize)"#, b"");
    test(r#"not defined hash.crc32(5, filesize)"#, b"a");
    test(r#"not defined hash.crc32(-1, filesize)"#, b"a");
    test(r#"not defined hash.crc32(0, -1)"#, b"a");
}
