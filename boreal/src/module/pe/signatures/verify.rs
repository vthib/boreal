//! Helpers related to verification of authenticode signatures
//!
//! This follows the information described in multiple places:
//!
//! Official microsoft doc:
//! <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>
use const_oid::db::rfc5912;
use md5::digest::Digest;
use rsa::signature::hazmat::PrehashVerifier;
use rsa::traits::SignatureScheme;
use rsa::RsaPublicKey;

use super::asn1;

const ECDSA_WITH_SHA_1: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");

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

    let digest_algo = digest_algo.map(|v| v.oid);

    match (digest_algo, &signature_algo.oid) {
        // RSA
        (Some(rfc5912::ID_MD_5), &rfc5912::RSA_ENCRYPTION)
        | (_, &rfc5912::MD_5_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<md5::Md5>(spki, signature, data))
        }
        (Some(rfc5912::ID_SHA_1), &rfc5912::RSA_ENCRYPTION)
        | (_, &rfc5912::SHA_1_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<sha1::Sha1>(spki, signature, data))
        }
        (Some(rfc5912::ID_SHA_256), &rfc5912::RSA_ENCRYPTION)
        | (_, &rfc5912::SHA_256_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<sha2::Sha256>(spki, signature, data))
        }
        (Some(rfc5912::ID_SHA_384), &rfc5912::RSA_ENCRYPTION)
        | (_, &rfc5912::SHA_384_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<sha2::Sha384>(spki, signature, data))
        }
        (Some(rfc5912::ID_SHA_512), &rfc5912::RSA_ENCRYPTION)
        | (_, &rfc5912::SHA_512_WITH_RSA_ENCRYPTION) => {
            Some(verify_rsa_key::<sha2::Sha512>(spki, signature, data))
        }
        // EC
        (Some(rfc5912::ID_SHA_1), &rfc5912::ID_EC_PUBLIC_KEY) | (_, &ECDSA_WITH_SHA_1) => {
            let data = sha1::Sha1::digest(data);
            verify_ecdsa_key(spki, signature, &data)
        }
        (Some(rfc5912::ID_SHA_256), &rfc5912::ID_EC_PUBLIC_KEY)
        | (_, &rfc5912::ECDSA_WITH_SHA_256) => {
            let data = sha2::Sha256::digest(data);
            verify_ecdsa_key(spki, signature, &data)
        }
        (Some(rfc5912::ID_SHA_384), &rfc5912::ID_EC_PUBLIC_KEY)
        | (_, &rfc5912::ECDSA_WITH_SHA_384) => {
            let data = sha2::Sha384::digest(data);
            verify_ecdsa_key(spki, signature, &data)
        }
        (Some(rfc5912::ID_SHA_512), &rfc5912::ID_EC_PUBLIC_KEY)
        | (_, &rfc5912::ECDSA_WITH_SHA_512) => {
            let data = sha2::Sha512::digest(data);
            verify_ecdsa_key(spki, signature, &data)
        }
        // DSA
        (Some(rfc5912::ID_SHA_1), &rfc5912::ID_DSA) | (_, &rfc5912::DSA_WITH_SHA_1) => {
            let data = sha1::Sha1::digest(data);
            Some(verify_dsa_key(spki, signature, &data))
        }
        (Some(rfc5912::ID_SHA_256), &rfc5912::ID_DSA) | (_, &rfc5912::DSA_WITH_SHA_256) => {
            let data = sha2::Sha256::digest(data);
            Some(verify_dsa_key(spki, signature, &data))
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

fn verify_dsa_key(spki: spki::SubjectPublicKeyInfoRef, signature: &[u8], data: &[u8]) -> bool {
    let Ok(key) = dsa::VerifyingKey::try_from(spki) else {
        return false;
    };
    let Ok(signature) = dsa::Signature::try_from(signature) else {
        return false;
    };

    key.verify_prehash(data, &signature).is_ok()
}

fn verify_ecdsa_key(
    spki: spki::SubjectPublicKeyInfoRef,
    signature: &[u8],
    data: &[u8],
) -> Option<bool> {
    let Some(param) = spki.algorithm.parameters else {
        return Some(false);
    };
    let Ok(curve) = param.decode_as::<asn1::ObjectIdentifier>() else {
        return Some(false);
    };

    match curve {
        rfc5912::SECP_256_R_1 => {
            let Ok(key) = p256::ecdsa::VerifyingKey::try_from(spki) else {
                return Some(false);
            };
            let Ok(signature) = p256::ecdsa::DerSignature::from_bytes(signature) else {
                return Some(false);
            };

            Some(key.verify_prehash(data, &signature).is_ok())
        }
        rfc5912::SECP_384_R_1 => {
            let Ok(key) = p384::ecdsa::VerifyingKey::try_from(spki) else {
                return Some(false);
            };
            let Ok(signature) = p384::ecdsa::DerSignature::from_bytes(signature) else {
                return Some(false);
            };

            Some(key.verify_prehash(data, &signature).is_ok())
        }
        _ => None,
    }
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
