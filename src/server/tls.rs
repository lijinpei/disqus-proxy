use crate::{error, Config};
use rustls::internal::pemfile::{certs, rsa_private_keys};
use rustls::{NoClientAuth, ServerConfig};

pub(crate) fn load_tls(conf: &Config) -> Result<ServerConfig, error::MainError> {
use std::io::BufReader;
use std::fs::File;

    let mut cert = match conf.tls_cert {
        Some(ref path) => {
            let res = File::open(path);
            match res {
                Ok(file) => {
                    BufReader::new(file)
                },
                Err(err) => {
                    return Err(error::MainError::TlsCertFileOpenFail(err));
                },
            }
        },
        None => {
            return Err(error::MainError::NoTlsCertFileSpecified);
        }
    };

    let mut key = match conf.tls_key {
        Some(ref path) => {
            let res = File::open(path);
            match res {
                Ok(file) => {
                    BufReader::new(file)
                },
                Err(err) => {
                    return Err(error::MainError::TlsKeyFileOpenFail(err));
                },
            }
        },
        None => {
            return Err(error::MainError::NoTlsKeyFileSpecified);
        }
    };

    let mut config = ServerConfig::new(NoClientAuth::new());
    let cert_chain = certs(&mut cert).unwrap();
    let mut keys = rsa_private_keys(&mut key).unwrap();
    config.set_single_cert(cert_chain, keys.remove(0)).unwrap();

    Ok(config)
}
