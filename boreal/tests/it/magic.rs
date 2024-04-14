use crate::libyara_compat::util::{ELF32_FILE, ELF32_SHAREDOBJ, PE32_FILE, TEXT_1024_BYTES};
use crate::utils::check;

#[track_caller]
fn test(cond: &str, data: &[u8]) {
    check(
        &format!(
            r#"
import "magic"

rule test {{
    condition: {cond}
}}"#,
        ),
        data,
        true,
    );
}

#[test]
fn test_mime_type() {
    test(r#"magic.mime_type() == "application/x-empty""#, b"");
    test(
        r#"magic.mime_type() == "application/x-executable""#,
        ELF32_FILE,
    );
    test(
        r#"magic.mime_type() == "application/x-sharedlib""#,
        ELF32_SHAREDOBJ,
    );
    test(r#"magic.mime_type() == "application/x-dosexec""#, PE32_FILE);
    test(
        r#"magic.mime_type() == "text/plain""#,
        TEXT_1024_BYTES.as_bytes(),
    );
}

#[test]
fn test_type() {
    test(r#"magic.type() == "empty""#, b"");
    test(
        r#"magic.type() == "ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV)""#,
        ELF32_FILE,
    );
    test(
        r#"magic.type() == "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)""#,
        ELF32_SHAREDOBJ,
    );
    test(
        r#"magic.type() == "MS-DOS executable PE32 executable (GUI) Intel 80386, for MS Windows""#,
        PE32_FILE,
    );
    test(
        r#"magic.type() == "ASCII text""#,
        TEXT_1024_BYTES.as_bytes(),
    );
}
