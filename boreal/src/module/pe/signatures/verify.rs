//! Helpers related to verification of authenticode signatures
//!
//! This follows the information described in multiple places:
//!
//! Official microsoft doc:
//! <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>
use const_oid::db::rfc5912;
use rsa::traits::SignatureScheme;
use rsa::RsaPublicKey;
use sha1::Digest;

use super::asn1;

pub fn verify_signer_info(
    info: &asn1::SignerInfo,
    certs: &[asn1::CertificateWithThumbprint],
) -> Option<bool> {
    let chain = super::CertificateChain::new(certs, &info.sid);

    for (cert, issuer) in chain.0.iter().zip(chain.0.iter().skip(1)) {
        if !verify_signature(
            &issuer.cert,
            None,
            &cert.cert.signature_algorithm,
            cert.cert.signature.raw_bytes(),
            cert.cert.cert_raw,
        )? {
            return Some(false);
        }
    }

    let Some(first) = chain.0.first() else {
        return Some(false);
    };

    let Some(der) = info
        .signed_attrs
        .as_ref()
        .and_then(signed_attrs_to_signature_der)
    else {
        return Some(false);
    };

    verify_signature(
        &first.cert,
        Some(&info.digest_alg),
        &info.signature_algorithm,
        info.signature.as_bytes(),
        &der,
    )
}

fn signed_attrs_to_signature_der(sa: &asn1::SignedAttrs) -> Option<Vec<u8>> {
    use der::Encode;

    let mut res = Vec::with_capacity(sa.value.len() + 2);

    let header = der::Header::new(der::Tag::Set, sa.value.len()).ok()?;
    header.encode(&mut res).ok()?;
    res.extend(sa.value);

    Some(res)
}

fn verify_signature(
    cert: &asn1::Certificate,
    digest_algo: Option<&asn1::AlgorithmIdentifierRef>,
    signature_algo: &asn1::AlgorithmIdentifierRef,
    signature: &[u8],
    data: &[u8],
) -> Option<bool> {
    let spki = cert.tbs_certificate.subject_public_key_info;
    let Ok(spki) = spki.decode_as::<spki::SubjectPublicKeyInfoRef>() else {
        return Some(false);
    };

    match (digest_algo.map(|v| &v.oid), &signature_algo.oid) {
        (Some(&rfc5912::ID_MD_5), &rfc5912::RSA_ENCRYPTION)
        | (_, &rfc5912::MD_5_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<md5::Md5>(spki, signature, data))
        }
        (Some(&rfc5912::ID_SHA_1), &rfc5912::RSA_ENCRYPTION)
        | (_, &rfc5912::SHA_1_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<sha1::Sha1>(spki, signature, data))
        }
        (Some(&rfc5912::ID_SHA_256), &rfc5912::RSA_ENCRYPTION)
        | (_, &rfc5912::SHA_256_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<sha2::Sha256>(spki, signature, data))
        }
        (Some(&rfc5912::ID_SHA_384), &rfc5912::RSA_ENCRYPTION)
        | (_, &rfc5912::SHA_384_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<sha2::Sha384>(spki, signature, data))
        }
        (Some(&rfc5912::ID_SHA_512), &rfc5912::RSA_ENCRYPTION)
        | (None, &rfc5912::SHA_512_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<sha2::Sha512>(spki, signature, data))
        }
        _ => None,
    }
}

fn verify_rsa_key<D: Digest + const_oid::AssociatedOid>(
    spki: spki::SubjectPublicKeyInfoRef,
    signature: &[u8],
    data: &[u8],
) -> bool {
    let Ok(pubkey) = RsaPublicKey::try_from(spki) else {
        return false;
    };

    let data = D::digest(data);
    // First try with a normal signature
    if rsa::pkcs1v15::Pkcs1v15Sign::new::<D>()
        .verify(&pubkey, &data, signature)
        .is_ok()
    {
        return true;
    }

    // Otherwise, try with an unprefixed signature. This is annoying but i'm not sure
    // we can distinguish the two before-hand.
    rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed()
        .verify(&pubkey, &data, signature)
        .is_ok()
}

/// Check the digest of a given data against an expected value
pub fn check_digest(alg: &asn1::ObjectIdentifier, data: &[u8], expected: &[u8]) -> bool {
    if alg == &rfc5912::ID_MD_5 {
        &*md5::Md5::digest(data) == expected
    } else if alg == &rfc5912::ID_SHA_1 {
        &*sha1::Sha1::digest(data) == expected
    } else if alg == &rfc5912::ID_SHA_256 {
        &*sha2::Sha256::digest(data) == expected
    } else if alg == &rfc5912::ID_SHA_384 {
        &*sha2::Sha384::digest(data) == expected
    } else if alg == &rfc5912::ID_SHA_512 {
        &*sha2::Sha512::digest(data) == expected
    } else {
        false
    }
}
