//! Outbound TLS trusts the operating system's store and nothing else.
//!
//! A local HTTPS server presents a certificate from a CA generated here, which
//! no real trust store contains. The checks, in one test because they change
//! process environment (`SSL_CERT_FILE`, `SSL_CERT_DIR`):
//!
//! 1. With the host's own store, the connection is refused on the certificate
//!    (the negative control: a client that accepted this would trust anything).
//! 2. With `SSL_CERT_FILE` naming the test CA, the same request succeeds.
//! 3. The pinned client (`create_pinned_agent`) is refused with the host
//!    store even when the leaf SPKI is pinned, because the pin check runs only
//!    after the WebPKI chain check; with the test CA injected, it succeeds.
//! 4. With `SSL_CERT_FILE` naming a file without certificates, building a
//!    client fails with `NoTrustedRoots`, naming `ca-certificates` and
//!    `SSL_CERT_FILE`, instead of falling back to bundled roots.
#![cfg(not(target_arch = "wasm32"))]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use wsc::WSError;
use wsc::keyless::PinningConfig;
use wsc::keyless::transport::create_pinned_agent;

struct TestPki {
    ca_pem: String,
    leaf_der: Vec<u8>,
    leaf_key_der: Vec<u8>,
    leaf_spki_sha256: String,
}

fn test_pki() -> TestPki {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "sigil tls_trust_store test CA");
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap())
        .unwrap();

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();

    TestPki {
        ca_pem: ca.pem(),
        leaf_der: leaf.der().to_vec(),
        leaf_key_der: leaf_key.serialize_der(),
        leaf_spki_sha256: hex::encode(Sha256::digest(
            pem::parse(leaf_key.public_key_pem()).unwrap().contents(),
        )),
    }
}

/// Serves `200 ok` over TLS on 127.0.0.1 for every connection; failed
/// handshakes are dropped. Returns the port.
fn spawn_server(pki: &TestPki) -> u16 {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                pki.leaf_der.clone(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(pki.leaf_key_der.clone().into()),
        )
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let config = config.clone();
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, stream);
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

fn get(agent: &ureq::Agent, port: u16) -> Result<String, String> {
    agent
        .get(&format!("https://localhost:{port}/"))
        .call()
        .map_err(|e| e.to_string())
        .and_then(|r| r.into_body().read_to_string().map_err(|e| e.to_string()))
}

fn is_untrusted_cert(err: &str) -> bool {
    err.contains("UnknownIssuer") || err.contains("invalid peer certificate")
}

fn set_env(key: &str, value: Option<&std::path::Path>) {
    // SAFETY: this test binary holds a single test, so no other thread reads
    // the environment while it is changed. The server threads never read it.
    unsafe {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}

#[test]
fn outbound_tls_trusts_the_os_store_only() {
    let pki = test_pki();
    let port = spawn_server(&pki);
    let dir = std::env::temp_dir().join(format!("sigil-tls-trust-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_file = dir.join("test-ca.pem");
    std::fs::write(&ca_file, &pki.ca_pem).unwrap();
    let empty_file = dir.join("no-certs.pem");
    std::fs::write(&empty_file, "not a certificate\n").unwrap();
    let pins = || PinningConfig::custom(vec![pki.leaf_spki_sha256.clone()], "localhost".into());

    // 1. Host store: the test CA is not trusted.
    set_env("SSL_CERT_FILE", None);
    set_env("SSL_CERT_DIR", None);
    let agent = wsc::tls_roots::os_agent()
        .expect("the host trust store must hold roots for this test to mean anything");
    let err = get(&agent, port).expect_err("a certificate from an unknown CA was accepted");
    assert!(
        is_untrusted_cert(&err),
        "refused, but not on the certificate: {err}"
    );

    // 3a. Pinned client, host store: the pin matches the leaf, the chain does not.
    let pinned = create_pinned_agent(pins()).expect("pinned agent");
    let err = get(&pinned, port).expect_err("the pin alone let an unknown CA through");
    assert!(
        is_untrusted_cert(&err),
        "pinned refusal, but not on the certificate: {err}"
    );

    // 2. Test CA injected through SSL_CERT_FILE.
    set_env("SSL_CERT_FILE", Some(&ca_file));
    let agent = wsc::tls_roots::os_agent().expect("SSL_CERT_FILE trust store");
    assert_eq!(get(&agent, port).as_deref(), Ok("ok"));

    // 3b. Pinned client with the test CA injected and the leaf pinned.
    let pinned = create_pinned_agent(pins()).expect("pinned agent");
    assert_eq!(get(&pinned, port).as_deref(), Ok("ok"));

    // 4. A trust store with no certificates is an error, not a fallback.
    set_env("SSL_CERT_FILE", Some(&empty_file));
    match wsc::tls_roots::os_agent() {
        Err(WSError::NoTrustedRoots(msg)) => {
            assert!(msg.contains("ca-certificates"), "{msg}");
            assert!(msg.contains("SSL_CERT_FILE"), "{msg}");
        }
        Err(e) => panic!("empty trust store gave the wrong error: {e}"),
        Ok(_) => panic!("an empty trust store still produced a client: a fallback exists"),
    }
    match create_pinned_agent(pins()) {
        Err(WSError::NoTrustedRoots(_)) => {}
        Err(e) => panic!("pinned client, empty store: wrong error: {e}"),
        Ok(_) => panic!("pinned client built over an empty trust store"),
    }

    set_env("SSL_CERT_FILE", None);
    let _ = std::fs::remove_dir_all(&dir);
}
