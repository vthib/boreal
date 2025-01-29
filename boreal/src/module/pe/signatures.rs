//! Parsing helpers for PE signatures, in authenticode format.
//!
//! This follows the information described in multiple places:
//!
//! Official microsoft doc:
//! <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>
use std::collections::HashMap;
use std::fmt::Write;

use const_oid::db::{rfc3280, rfc4519, rfc5912};
use der::oid::db::DB;
use der::Decode;
use md5::Digest;
use object::read::pe::{DataDirectories, ImageNtHeaders, ImageOptionalHeader};
use object::{pe, Bytes, LittleEndian as LE, U16, U32};

use super::Value;
use crate::module::hex_encode;

mod asn1;
#[cfg(feature = "authenticode-verify")]
mod verify;

const MAX_PE_CERTS: usize = 16;

#[derive(Debug, Default)]
struct Signatures {
    sigs: Vec<Value>,
    signed: Option<bool>,
}

pub fn get_signatures(data_dirs: &DataDirectories, mem: &[u8]) -> Option<(Vec<Value>, Value)> {
    let dir = data_dirs.get(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    let (va, size) = dir.address_range();
    let va = va as usize;
    let size = size as usize;
    let end = va.checked_add(size)?;

    if va == 0 || va > mem.len() || size > mem.len() || end > mem.len() {
        return None;
    }

    let mut data = Bytes(mem.get(va..end)?);
    let mut signatures = Signatures::default();
    #[cfg(feature = "authenticode-verify")]
    {
        signatures.signed = Some(false);
    }

    // Data contains a list of WIN_CERTIFICATE objects:
    // <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate>
    // Each subsequent one is aligned on a 8-bytes boundary.
    while !data.is_empty() {
        let mut length: u32 = data.read::<U32<LE>>().ok()?.get(LE);
        // length contains the length + rev + type, so remove it
        if length <= 8 {
            break;
        }
        length -= 8;

        let rev: u16 = data.read::<U16<LE>>().ok()?.get(LE);
        let cert_type: u16 = data.read::<U16<LE>>().ok()?.get(LE);
        let cert_data = data.read_slice::<u8>(length as usize).ok()?;

        // revision is 2.0 and cert type is PKCS_SIGNED_DATA
        if rev == 0x0200 && cert_type == 0x0002 {
            add_signatures(mem, cert_data, &mut signatures);
        }

        let offset = data.0.as_ptr() as usize - mem.as_ptr() as usize;
        let new_offset = align64(offset);
        data.skip(new_offset - offset).ok()?;
    }

    let is_signed = match signatures.signed {
        Some(is_signed) => Value::Integer(is_signed.into()),
        None => Value::Undefined,
    };

    Some((signatures.sigs, is_signed))
}

fn add_signatures(mem: &[u8], cert_data: &[u8], signatures: &mut Signatures) {
    // Do not use `ContentInfo::from_der` but use a SliceReader: this allows
    // ignoring a few trailing bytes from the cert_data which happens very frequently.
    let Ok(mut reader) = der::SliceReader::new(cert_data) else {
        return;
    };

    // Data should be ContentInfo, of type "signed data"
    let Ok(content_info) = asn1::ContentInfo::decode(&mut reader) else {
        return;
    };

    add_signatures_from_content_info(mem, &content_info, signatures);
}

fn add_signatures_from_content_info(
    mem: &[u8],
    content_info: &asn1::ContentInfo,
    signatures: &mut Signatures,
) {
    if signatures.sigs.len() >= MAX_PE_CERTS {
        return;
    }
    if content_info.content_type != asn1::ID_SIGNED_DATA {
        return;
    }
    let Ok(mut signed_data) = content_info.content.decode_as::<asn1::SignedData>() else {
        return;
    };

    // According to the official, the SignedData content info contains a "SpcIndirectDataContent".
    let spc_indirect_data = signed_data.get_spc_indirect_data();

    // This SpcIndirectDataContent contains the authenticode digest.
    let digest = spc_indirect_data
        .as_ref()
        .map(|v| v.message_digest.digest.as_bytes());
    let digest_alg_oid = spc_indirect_data
        .as_ref()
        .map(|v| &v.message_digest.digest_algorithm.oid);

    // Build the list of certificates: this will be used to get the certificates chains
    // for the signer info and counter signatures.
    let mut certificate_chain = signed_data
        .certificates
        .take()
        .map(|v| v.0)
        .unwrap_or_default();

    // According the the authenticode doc, there is one and only one SignerInfo object.
    // We do not reject the parsing if it is missing however: we can still return a lot
    // of useful information.
    let signer_info = signed_data.signer_infos.iter().next();

    // Compute the signer_info values before adding the countersignatures to the certificate chain,
    // to avoid impacting the chain computation.
    let (signer_info_value, first_cert) = match signer_info {
        Some(v) => signer_info_to_value(v, &certificate_chain),
        None => (Value::Undefined, None),
    };
    let mut map = first_cert.map(|v| cert_to_map(v, true)).unwrap_or_default();

    let mut countersigs = Vec::new();
    if let Some(signer_info) = signer_info {
        add_countersigs(signer_info, &certificate_chain, &mut countersigs);
        add_ms_countersigs(signer_info, &mut certificate_chain, &mut countersigs);
    }

    // Compute the authenticode digest, this will make it possible to compare it to
    // the stored one.
    let file_digest = digest_alg_oid.and_then(|oid| {
        if oid == &rfc5912::ID_MD_5 {
            compute_authenticode_hash::<md5::Md5>(mem)
        } else if oid == &rfc5912::ID_SHA_1 {
            compute_authenticode_hash::<sha1::Sha1>(mem)
        } else if oid == &rfc5912::ID_SHA_256 {
            compute_authenticode_hash::<sha2::Sha256>(mem)
        } else if oid == &rfc5912::ID_SHA_384 {
            compute_authenticode_hash::<sha2::Sha384>(mem)
        } else if oid == &rfc5912::ID_SHA_512 {
            compute_authenticode_hash::<sha2::Sha512>(mem)
        } else {
            None
        }
    });

    let certificates: Vec<Value> = certificate_chain
        .iter()
        .map(|v| cert_to_map(v, false))
        .map(Value::Object)
        .collect();

    #[cfg(feature = "authenticode-verify")]
    let verified = {
        let message_digest = signer_info.and_then(asn1::SignerInfo::get_message_digest);

        let mut verified = true;
        // file digest matches
        verified = verified
            && match (digest, &file_digest) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            };
        // message digest matches
        verified = verified
            && match (
                digest_alg_oid,
                message_digest,
                signed_data.encap_content_info.econtent,
            ) {
                (Some(alg), Some(dig), Some(content)) => {
                    verify::check_digest(alg, content.value(), dig)
                }
                _ => false,
            };
        verified = verified
            && signer_info.is_some_and(|info| {
                verify::verify_signer_info(info, &certificate_chain).unwrap_or(false)
            });

        if verified {
            signatures.signed = Some(true);
        }
        Value::Integer(verified.into())
    };
    #[cfg(not(feature = "authenticode-verify"))]
    let verified = Value::Undefined;

    map.extend([
        ("number_of_certificates", certificates.len().into()),
        ("certificates", Value::Array(certificates)),
        ("signer_info", signer_info_value),
        ("number_of_countersignatures", countersigs.len().into()),
        ("countersignatures", Value::Array(countersigs)),
        (
            "digest_alg",
            digest_alg_oid
                .and_then(get_oid_name)
                .map(Value::bytes)
                .into(),
        ),
        ("digest", digest.map(hex_encode).map(Value::Bytes).into()),
        (
            "file_digest",
            file_digest.map(hex_encode).map(Value::Bytes).into(),
        ),
        ("verified", verified),
    ]);
    signatures.sigs.push(Value::Object(map));

    // Signatures can be nested, with for example one containing a sha1 authenticode digest and
    // another containing a sha256 authenticode digest.
    if let Some(signer_info) = signer_info {
        add_nested_signatures(mem, signer_info, signatures);
    }
}

fn add_nested_signatures(mem: &[u8], signer_info: &asn1::SignerInfo, signatures: &mut Signatures) {
    if let Some(attrs) = signer_info.unsigned_attrs.as_ref() {
        for attr in attrs.iter() {
            if attr.oid == asn1::ID_SPC_NESTED_SIGNATURE {
                for value in attr.values.iter() {
                    if let Ok(content_info) = value.decode_as::<asn1::ContentInfo>() {
                        add_signatures_from_content_info(mem, &content_info, signatures);
                    }
                }
            }
        }
    }
}

fn add_countersigs(
    info: &asn1::SignerInfo,
    certs: &[asn1::CertificateWithThumbprint],
    countersigs: &mut Vec<Value>,
) {
    // See §Authenticode timestamp in the docx doc
    if let Some(attrs) = info.unsigned_attrs.as_ref() {
        for attr in attrs.iter() {
            if attr.oid != asn1::ID_COUNTERSIGNATURE {
                continue;
            }

            for value in attr.values.iter() {
                // See PKCS#9: RFC 2985 5.3.6: the countersignature attribute
                // contains a SignerInfo object.
                let Ok(signer_info) = value.decode_as::<asn1::SignerInfo>() else {
                    continue;
                };

                countersigs.push(Value::Object(countersig_to_map(
                    &signer_info,
                    certs,
                    None,
                    #[cfg(feature = "authenticode-verify")]
                    |digest| {
                        verify::check_digest(
                            &signer_info.digest_alg.oid,
                            info.signature.as_bytes(),
                            digest,
                        )
                    },
                    #[cfg(not(feature = "authenticode-verify"))]
                    |_| false,
                )));
            }
        }
    }
}

fn add_ms_countersigs<'a>(
    info: &asn1::SignerInfo<'a>,
    certs: &mut Vec<asn1::CertificateWithThumbprint<'a>>,
    countersigs: &mut Vec<Value>,
) {
    if let Some(attrs) = info.unsigned_attrs.as_ref() {
        for attr in attrs.iter() {
            if attr.oid != asn1::ID_COUNTERSIGN {
                continue;
            }

            for value in attr.values.iter() {
                if let Ok(content_info) = value.decode_as::<asn1::ContentInfo>() {
                    // TODO: handle countersig in CMS format
                    parse_ms_countersig(info, &content_info, certs, countersigs);
                }
            }
        }
    }
}

fn parse_ms_countersig<'a>(
    #[allow(unused_variables)] parent_signer_info: &asn1::SignerInfo<'a>,
    content_info: &asn1::ContentInfo<'a>,
    certs: &mut Vec<asn1::CertificateWithThumbprint<'a>>,
    countersigs: &mut Vec<Value>,
) {
    if content_info.content_type != asn1::ID_SIGNED_DATA {
        return;
    }
    let Ok(mut signed_data) = content_info.content.decode_as::<asn1::SignedData>() else {
        return;
    };

    let mut counter_certificates = signed_data
        .certificates
        .take()
        .map(|v| v.0)
        .unwrap_or_default();

    let Some(signer_info) = signed_data.signer_infos.iter().next() else {
        return;
    };

    // Find the digest from the TstInfo object store in the signed_data content
    if signed_data.encap_content_info.econtent_type != asn1::ID_CT_TSTINFO {
        return;
    }
    let Some(tst_info) = signed_data.encap_content_info.econtent.and_then(|v| {
        let octet_string = v.decode_as::<asn1::OctetStringRef<'_>>().ok()?;
        asn1::TstInfo::from_der(octet_string.as_bytes()).ok()
    }) else {
        return;
    };

    let tst_info_digest = tst_info.message_imprint.hashed_message;
    let tst_info_digest_alg = &tst_info.message_imprint.hash_algorithm.oid;

    let sign_time = tst_info.gen_time.0.to_unix_duration().as_secs();

    let mut countersig = countersig_to_map(
        signer_info,
        &counter_certificates,
        Some(sign_time),
        #[cfg(feature = "authenticode-verify")]
        |digest| {
            let Some(content) = &signed_data.encap_content_info.econtent else {
                return false;
            };
            // Check the digest of the countersignature
            verify::check_digest(&signer_info.digest_alg.oid, content.value(), digest) &&
            // Check the digest from the TstInfo object as well, it must match the original signature
            verify::check_digest(tst_info_digest_alg, parent_signer_info.signature.as_bytes(), tst_info_digest.as_bytes())
        },
        #[cfg(not(feature = "authenticode-verify"))]
        |_| false,
    );

    certs.append(&mut counter_certificates);
    countersig.extend([
        ("digest", Value::Bytes(hex_encode(tst_info_digest))),
        (
            "digest_alg",
            get_oid_name(tst_info_digest_alg).map(Value::bytes).into(),
        ),
    ]);

    countersigs.push(Value::Object(countersig));
}

fn countersig_to_map<F>(
    info: &asn1::SignerInfo,
    certs: &[asn1::CertificateWithThumbprint],
    sign_time: Option<u64>,
    check_digest: F,
) -> HashMap<&'static str, Value>
where
    F: FnOnce(&[u8]) -> bool,
{
    let sign_time = sign_time.or_else(|| info.get_signing_time().map(time_to_ts));
    let digest = info.get_message_digest();

    let chain = CertificateChain::new(certs, &info.sid);

    #[cfg(feature = "authenticode-verify")]
    let verified = Value::Integer(
        (
            // Has signing time
            sign_time.is_some() &&
                // Has a signer cert
                !chain.0.is_empty() &&
                // message digest matches
                digest.is_some_and(check_digest) &&
                verify::verify_signer_info(info, certs).unwrap_or(false)
        )
        .into(),
    );
    #[cfg(not(feature = "authenticode-verify"))]
    let verified = {
        drop(check_digest);
        Value::Undefined
    };

    [
        ("verified", verified),
        ("sign_time", sign_time.into()),
        ("digest", digest.map(hex_encode).map(Value::Bytes).into()),
        (
            "digest_alg",
            get_oid_name(&info.digest_alg.oid).map(Value::bytes).into(),
        ),
        ("length_of_chain", chain.0.len().into()),
        ("chain", chain.into_value()),
    ]
    .into()
}

fn signer_info_to_value<'a, 'b>(
    info: &asn1::SignerInfo,
    certs: &'a [asn1::CertificateWithThumbprint<'b>],
) -> (Value, Option<&'a asn1::CertificateWithThumbprint<'b>>) {
    // See authenticode doc: `SignerInfo` contains a `SpcSpOpusInfo` object that
    // holds the program name.
    let spc_sp_opus_info = info
        .get_signed_attr(&asn1::ID_SPC_SP_OPUS_INFO)
        .and_then(|value| value.decode_as::<asn1::SpcSpOpusInfo>().ok());

    let program_name: Option<String> = spc_sp_opus_info
        .as_ref()
        .and_then(|v| v.program_name.as_ref())
        .map(|v| match v {
            asn1::SpcString::Unicode(v) => v.chars().collect(),
            asn1::SpcString::Ascii(v) => v.as_str().to_owned(),
        });

    let digest = info.get_message_digest();

    let chain = CertificateChain::new(certs, &info.sid);
    let first_cert = chain.0.first().copied();

    let res = Value::object([
        ("program_name", program_name.map(Value::bytes).into()),
        ("digest", digest.map(hex_encode).map(Value::Bytes).into()),
        (
            "digest_alg",
            get_oid_name(&info.digest_alg.oid).map(Value::bytes).into(),
        ),
        ("length_of_chain", chain.0.len().into()),
        ("chain", chain.into_value()),
    ]);
    (res, first_cert)
}

fn cert_to_map(
    cert: &asn1::CertificateWithThumbprint,
    with_valid_on: bool,
) -> HashMap<&'static str, Value> {
    let version = cert.cert.tbs_certificate.version + 1;
    let serial_number = serial_number_to_string(cert.cert.tbs_certificate.serial_number.as_bytes());

    let not_before = time_to_ts(cert.cert.tbs_certificate.validity.not_before);
    let not_after = time_to_ts(cert.cert.tbs_certificate.validity.not_after);

    let algo = &cert.cert.signature_algorithm.oid;
    let algorithm_oid = algo.to_string().into_bytes();

    [
        ("thumbprint", Value::bytes(cert.thumbprint.clone())),
        (
            "issuer",
            name_to_openssl_format(&cert.cert.tbs_certificate.issuer)
                .into_bytes()
                .into(),
        ),
        (
            "subject",
            name_to_openssl_format(&cert.cert.tbs_certificate.subject)
                .into_bytes()
                .into(),
        ),
        ("version", version.into()),
        ("algorithm", get_oid_name(algo).map(Value::bytes).into()),
        ("algorithm_oid", algorithm_oid.into()),
        ("serial", serial_number.map(String::into_bytes).into()),
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

struct CertificateChain<'a, 'b>(Vec<&'a asn1::CertificateWithThumbprint<'b>>);

impl<'a, 'b> CertificateChain<'a, 'b> {
    /// Find a certificate matching the predicate, then build a chain of certificates
    /// by matching the issuer of a certificate with the subject of the next certificate.
    fn new(
        certificates: &'a [asn1::CertificateWithThumbprint<'b>],
        signer_identifier: &asn1::SignerIdentifier,
    ) -> Self {
        let first_cert = match signer_identifier {
            asn1::SignerIdentifier::IssuerAndSerialNumber(ident) => certificates.iter().find(|c| {
                c.cert.tbs_certificate.issuer == ident.issuer
                    && c.cert.tbs_certificate.serial_number == ident.serial_number
            }),
            asn1::SignerIdentifier::SubjectKeyIdentifier(_) => None,
        };
        let Some(mut cert) = first_cert else {
            return Self(Vec::new());
        };

        let mut certs = Vec::with_capacity(certificates.len());
        certs.push(cert);
        while cert.cert.tbs_certificate.issuer != cert.cert.tbs_certificate.subject {
            match certificates
                .iter()
                .find(|c| c.cert.tbs_certificate.subject == cert.cert.tbs_certificate.issuer)
            {
                Some(v) => cert = v,
                None => break,
            }
            certs.push(cert);
        }

        Self(certs)
    }

    fn into_value(self) -> Value {
        Value::Array(
            self.0
                .into_iter()
                .map(|cert| Value::Object(cert_to_map(cert, false)))
                .collect(),
        )
    }
}

/// Compute the authenticode hash of the given file.
fn compute_authenticode_hash<D: Digest>(mem: &[u8]) -> Option<Vec<u8>> {
    let dos_header = pe::ImageDosHeader::parse(mem).ok()?;

    // Get the magic to find if this is a PE32 or PE64
    let magic_offset = (dos_header.nt_headers_offset() + 4 + 20) as usize;
    let magic = Bytes(mem).read_at::<U16<LE>>(magic_offset).ok()?.get(LE);

    match magic {
        pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            compute_authenticode_hash_inner::<D, pe::ImageNtHeaders32>(mem, dos_header)
        }
        pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
            compute_authenticode_hash_inner::<D, pe::ImageNtHeaders64>(mem, dos_header)
        }
        _ => None,
    }
}

fn compute_authenticode_hash_inner<D: Digest, HEADERS: ImageNtHeaders>(
    mem: &[u8],
    dos_header: &pe::ImageDosHeader,
) -> Option<Vec<u8>> {
    // The algorithm implemented here is not exactly the one documented by Microsoft
    // in the official authenticode doc: instead of sorting the sections and hashing only
    // their contents, we hash all the contents and skip only the cert table.
    //
    // This is the algorithm implemented in several other codebase, and seems to work on
    // more esoteric files when the official algo does not match.
    let mut offset = dos_header.nt_headers_offset().into();
    let (nt_headers, data_dirs) = HEADERS::parse(mem, &mut offset).ok()?;
    let opt_hdr = nt_headers.optional_header();

    // Offset to the checksum field
    //
    // 4: signature size
    // 20: file header size
    // 64: offset to checksum in optional header
    let checksum_offset = (dos_header.nt_headers_offset() as usize) + 4 + 20 + 64;

    // Offset to the certificate table entry.
    //
    // 64: offset from the checksum to the cert table offset for the 32 bits verion.
    // +16 for the 64 bits version
    let mut cert_table_entry_offset = checksum_offset + 64;
    if opt_hdr.magic() == pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        cert_table_entry_offset += 16;
    }

    // Get size of the cert table
    let dir = data_dirs.get(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    let cert_table_offset = dir.virtual_address.get(LE) as usize;
    let cert_table_size = dir.size.get(LE) as usize;

    let mut hasher = D::new();

    // hash up to the checksum
    hasher.update(mem.get(..checksum_offset)?);
    // Then hash up to the cert table entry
    hasher.update(mem.get((checksum_offset + 4)..cert_table_entry_offset)?);
    // Then hash up to the end of the headers
    hasher.update(mem.get((cert_table_entry_offset + 8)..(opt_hdr.size_of_headers() as usize))?);
    // Then hash up to the start of the cert table
    hasher.update(mem.get((opt_hdr.size_of_headers() as usize)..(cert_table_offset))?);
    // Then hash from the end of the cert table to the end of the file
    hasher.update(mem.get((cert_table_offset + cert_table_size)..)?);

    Some(hasher.finalize().to_vec())
}

fn serial_number_to_string(serial: &[u8]) -> Option<String> {
    if serial.is_empty() || serial.len() > 20 {
        return None;
    }

    let mut out = String::with_capacity(serial.len() * 3);
    for c in serial {
        if !out.is_empty() {
            out.push(':');
        }
        let _ = write!(out, "{c:02x}");
    }

    Some(out)
}

fn time_to_ts(time: asn1::Time) -> u64 {
    match time {
        asn1::Time::UtcTime(v) => v.to_unix_duration().as_secs(),
        asn1::Time::GeneralTime(v) => v.to_unix_duration().as_secs(),
    }
}

// Align offset on 64-bit boundary
const fn align64(offset: usize) -> usize {
    (offset + 7) & !7
}

fn get_oid_name(oid: &asn1::ObjectIdentifier) -> Option<&[u8]> {
    match *oid {
        asn1::SHA1_WITH_RSA => Some(b"sha1WithRSA"),
        rfc5912::MD_2_WITH_RSA_ENCRYPTION => Some(b"md2WithRSAEncryption"),
        rfc5912::MD_5_WITH_RSA_ENCRYPTION => Some(b"md5WithRSAEncryption"),
        rfc5912::SHA_1_WITH_RSA_ENCRYPTION => Some(b"sha1WithRSAEncryption"),
        rfc5912::SHA_256_WITH_RSA_ENCRYPTION => Some(b"sha256WithRSAEncryption"),
        rfc5912::SHA_384_WITH_RSA_ENCRYPTION => Some(b"sha384WithRSAEncryption"),
        rfc5912::SHA_512_WITH_RSA_ENCRYPTION => Some(b"sha512WithRSAEncryption"),
        asn1::ECDSA_WITH_SHA_1 => Some(b"ecdsa-with-SHA1"),
        rfc5912::ECDSA_WITH_SHA_256 => Some(b"ecdsa-with-SHA256"),
        rfc5912::ECDSA_WITH_SHA_384 => Some(b"ecdsa-with-SHA384"),
        rfc5912::ECDSA_WITH_SHA_512 => Some(b"ecdsa-with-SHA512"),
        rfc5912::ID_MD_5 => Some(b"md5"),
        rfc5912::ID_SHA_1 => Some(b"sha1"),
        rfc5912::ID_SHA_256 => Some(b"sha256"),
        rfc5912::ID_SHA_384 => Some(b"sha384"),
        rfc5912::ID_SHA_512 => Some(b"sha512"),
        rfc5912::DSA_WITH_SHA_1 => Some(b"dsaWithSHA1"),
        rfc5912::DSA_WITH_SHA_256 => Some(b"dsa_with_SHA256"),
        _ => DB.by_oid(oid).map(str::as_bytes),
    }
}

fn get_rdn_name(oid: &asn1::ObjectIdentifier) -> Option<&str> {
    match *oid {
        rfc4519::C => Some("C"),
        rfc4519::CN => Some("CN"),
        rfc4519::L => Some("L"),
        rfc4519::O => Some("O"),
        rfc4519::OU => Some("OU"),
        rfc4519::ST => Some("ST"),
        rfc4519::STREET => Some("street"),
        rfc4519::UID => Some("UID"),
        rfc3280::EMAIL => Some("emailAddress"),
        asn1::JURISDICTION_L => Some("jurisdictionL"),
        asn1::JURISDICTION_ST => Some("jurisdictionST"),
        asn1::JURISDICTION_C => Some("jurisdictionC"),
        _ => DB.by_oid(oid),
    }
}

// Convert a "Name" into the right openssl format.
//
// This generates the same format as the legacy X509_NAME_oneline openssl function:
// - Prefix every RDN with '/'
// - do not do any escaping
fn name_to_openssl_format(name: &asn1::NameRef) -> String {
    let mut res = String::new();
    for rdn in name {
        for (i, atv) in rdn.iter().enumerate() {
            write!(&mut res, "{}", if i == 0 { '/' } else { '+' }).unwrap();
            match get_rdn_name(&atv.oid) {
                Some(key) => write!(&mut res, "{key}=").unwrap(),
                None => write!(&mut res, "{}=", atv.oid).unwrap(),
            }

            for b in atv.value.value() {
                if *b < b' ' || *b > b'~' {
                    write!(&mut res, "\\x{:02X}", *b).unwrap();
                } else {
                    res.push(*b as char);
                }
            }
        }
    }

    res
}

fn valid_on(args: Vec<Value>, not_before: u64, not_after: u64) -> Option<Value> {
    let mut args = args.into_iter();
    let timestamp: i64 = args.next()?.try_into().ok()?;
    let timestamp: u64 = timestamp.try_into().ok()?;

    Some(Value::Boolean(
        timestamp >= not_before && timestamp <= not_after,
    ))
}
