use std::collections::HashMap;

use authenticode_parser::{
    Authenticode, AuthenticodeArray, AuthenticodeVerify, Certificate, CounterSignatureVerify,
    Countersignature, InitializationToken, Signer,
};
use object::{pe, read::pe::DataDirectories};

use super::Value;

pub fn get_signatures(
    data_dirs: &DataDirectories,
    mem: &[u8],
    token: InitializationToken,
) -> Option<(Vec<Value>, bool)> {
    let dir = data_dirs.get(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    let (va, size) = dir.address_range();
    let va = va as usize;
    let size = size as usize;
    let end = va.checked_add(size)?;

    if va == 0 || va > mem.len() || size > mem.len() || end > mem.len() {
        return None;
    }

    // TODO: use parse instead of parse_pe as we have the payload already?
    let auth = authenticode_parser::parse_pe(&token, mem)?;
    Some(process_authenticode(&auth))
}

fn process_authenticode(auth: &AuthenticodeArray) -> (Vec<Value>, bool) {
    let mut signatures = Vec::new();
    // Whole pe is signed if at least one signature is signed.
    let mut is_signed = false;

    for sig in auth.signatures() {
        let verified = sig.verify_flags() == Some(AuthenticodeVerify::Valid);
        is_signed = is_signed || verified;

        let digest = sig.digest().map(hex::encode).map(Value::bytes);
        let digest_alg = sig.digest_alg().map(Value::bytes);
        let file_digest = sig.file_digest().map(hex::encode).map(Value::bytes);

        // TODO on length_of_chain or other lengths, behavior is not aligned:
        // yara does not save the length if the pointer is 0.
        let certs = process_certs(sig.certs());
        let signer_info = sig
            .signer()
            .as_ref()
            .map_or(Value::Undefined, signer_to_value);
        let countersigs: Vec<_> = sig.countersigs().iter().map(countersig_to_value).collect();

        let mut map = get_legacy_signer_data(sig);
        map.extend([
            ("verified", Value::Integer(verified.into())),
            ("digest_alg", digest_alg.unwrap_or(Value::Undefined)),
            ("digest", digest.unwrap_or(Value::Undefined)),
            ("file_digest", file_digest.unwrap_or(Value::Undefined)),
            ("number_of_certificates", certs.len().into()),
            ("certificates", Value::Array(certs)),
            ("signer_info", signer_info),
            ("number_of_countersignatures", countersigs.len().into()),
            ("countersignatures", Value::Array(countersigs)),
        ]);

        signatures.push(Value::Object(map));
    }

    (signatures, is_signed)
}

fn process_certs(certs: &[Certificate]) -> Vec<Value> {
    certs
        .iter()
        .map(|v| cert_to_map(v, false))
        .map(Value::Object)
        .collect()
}

fn signer_to_value(signer: &Signer) -> Value {
    let program_name = signer.program_name().map(Value::bytes);
    let digest = signer.digest().map(hex::encode).map(Value::bytes);
    let digest_alg = signer.digest_alg().map(Value::bytes);
    let chain = process_certs(signer.certificate_chain());

    Value::object([
        ("program_name", program_name.unwrap_or(Value::Undefined)),
        ("digest", digest.unwrap_or(Value::Undefined)),
        ("digest_alg", digest_alg.unwrap_or(Value::Undefined)),
        ("length_of_chain", chain.len().into()),
        ("chain", Value::Array(chain)),
    ])
}

fn countersig_to_value(countersig: &Countersignature) -> Value {
    let verified =
        Value::Integer((countersig.verify_flags() == Some(CounterSignatureVerify::Valid)).into());
    let sign_time = countersig.sign_time().into();
    let digest = countersig.digest().map(hex::encode).map(Value::bytes);
    let digest_alg = countersig.digest_alg().map(Value::bytes);
    let chain = process_certs(countersig.certificate_chain());

    Value::object([
        ("verified", verified),
        ("sign_time", sign_time),
        ("digest", digest.unwrap_or(Value::Undefined)),
        ("digest_alg", digest_alg.unwrap_or(Value::Undefined)),
        ("length_of_chain", chain.len().into()),
        ("chain", Value::Array(chain)),
    ])
}

fn get_legacy_signer_data(sig: &Authenticode) -> HashMap<&'static str, Value> {
    sig.signer()
        .as_ref()
        .and_then(|signer| signer.certificate_chain().first())
        .map(|v| cert_to_map(v, true))
        .unwrap_or_default()
}

fn cert_to_map(cert: &Certificate, with_valid_on: bool) -> HashMap<&'static str, Value> {
    let thumbprint_ascii = cert.sha1().map(hex::encode).map(Value::bytes);
    let not_before = cert.not_before();
    let not_after = cert.not_after();

    [
        ("thumbprint", thumbprint_ascii.unwrap_or(Value::Undefined)),
        ("issuer", cert.issuer().map(ToOwned::to_owned).into()),
        ("subject", cert.subject().map(ToOwned::to_owned).into()),
        ("version", (cert.version() + 1).into()),
        ("algorithm", cert.sig_alg().map(ToOwned::to_owned).into()),
        (
            "algorithm_oid",
            cert.sig_alg_oid().map(ToOwned::to_owned).into(),
        ),
        ("serial", cert.serial().map(ToOwned::to_owned).into()),
        ("not_before", not_before.into()),
        ("not_after", not_after.into()),
        (
            "valid_on",
            if with_valid_on {
                Value::function(move |_, args| valid_on(args, not_before, not_after))
            } else {
                Value::Undefined
            },
        ),
    ]
    .into()
}

fn valid_on(args: Vec<Value>, not_before: i64, not_after: i64) -> Option<Value> {
    let mut args = args.into_iter();
    let timestamp: i64 = args.next()?.try_into().ok()?;

    Some(Value::Boolean(
        timestamp >= not_before && timestamp <= not_after,
    ))
}
