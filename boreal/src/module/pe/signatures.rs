use authenticode_parser::{Authenticode, AuthenticodeArray};
use object::{pe, read::pe::DataDirectories};

use super::Value;

pub fn get_signatures(data_dirs: &DataDirectories, mem: &[u8]) -> Option<Vec<Value>> {
    let dir = data_dirs.get(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    let (va, size) = dir.address_range();
    let va = va as usize;
    let size = size as usize;
    let end = va.checked_add(size)?;

    if va == 0 || va > mem.len() || size > mem.len() || end > mem.len() {
        return None;
    }

    // FIXME: this shouldn't be done here
    let token = unsafe { authenticode_parser::InitializationToken::new() };

    // TODO: use parse instead of parse_pe as we have the payload already?
    let auth = authenticode_parser::parse_pe(&token, mem)?;

    let mut signatures = Vec::new();
    process_authenticode(&auth, &mut signatures);

    Some(signatures)
}

fn process_authenticode(auth: &AuthenticodeArray, signatures: &mut Vec<Value>) {
    for sig in auth.signatures() {
        signatures.push(signer_to_value(sig).unwrap_or_else(|| Value::object([])));
    }
}

fn signer_to_value(sig: &Authenticode) -> Option<Value> {
    let signer = sig.signer()?;
    let cert = signer.certificate_chain().get(0)?;

    let thumbprint_ascii = match cert.sha1() {
        Some(sha) => Value::bytes(hex::encode(sha)),
        None => Value::Undefined,
    };

    let not_before = cert.not_before();
    let not_after = cert.not_after();

    Some(Value::object([
        ("thumbprint", thumbprint_ascii.into()),
        ("issuer", cert.issuer().map(ToOwned::to_owned).into()),
        ("subject", cert.subject().map(ToOwned::to_owned).into()),
        ("version", (cert.version() + 1).into()),
        ("algorithm", cert.sig_alg().map(ToOwned::to_owned).into()),
        (
            "algorithm_oid",
            cert.sig_alg_oid().map(ToOwned::to_owned).into(),
        ),
        ("serial", cert.serial().map(ToOwned::to_owned).into()),
        (
            "valid_on",
            Value::function(move |_, args| valid_on(args, not_before, not_after)),
        ),
        ("not_before", cert.not_before().into()),
        ("not_after", cert.not_after().into()),
    ]))
}

fn valid_on(args: Vec<Value>, not_before: i64, not_after: i64) -> Option<Value> {
    let mut args = args.into_iter();
    let timestamp: i64 = args.next()?.try_into().ok()?;

    Some(Value::Boolean(
        timestamp >= not_before && timestamp <= not_after,
    ))
}
