mod tls;

use crate::{Config, error};

use actix_web::{App, server, HttpRequest, Responder};
use std::path::PathBuf;
use std::result::Result;
use std::net::SocketAddr;
use std::sync::Arc;

fn get_addr(conf: &Config) -> Result<SocketAddr, error::MainError> {
    let listen_addr = conf.listen_address.clone().ok_or(error::MainError::NoListenAddress)?;
    //let addr = listen_addr.parse::<std::net::Ipv4Addr>().map_err(|e| {error::MainError::ParseListenAddress(e)})?;
    let addr = listen_addr.parse::<std::net::Ipv4Addr>().map_err(|e| {error::MainError::ParseListenAddress(e)})?;
    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(addr, conf.listen_port.ok_or(error::MainError::NoListenPort)?))
}

// TODO: return a Result here
fn build_app(conf: Arc<Config>)-> App {
    App::new().resource("/", |r| r.f(greet)).resource("/{name}", |r| r.f(greet))
}

fn greet(req: &HttpRequest) -> impl Responder {
    let to = req.match_info().get("name").unwrap_or("World");
    format!("Hello {}!", to)
}

pub (crate) fn run_server(_conf_path: Option<PathBuf>, conf: Config) -> Result<(), error::MainError>{
    let addr = get_addr(&conf)?;
    let arc_conf = Arc::new(conf.clone());
    let server = server::new(move || {
        build_app(arc_conf.clone())
    });
    let server = if let Some(true) = conf.use_tls {
        let server_config = tls::load_tls(&conf)?;
        server.bind_rustls(addr, server_config).map_err(|e| { error::MainError::BindTlsAddrFail(e) })?
    } else {
        server.bind(addr).map_err(|e| { error::MainError::BindAddrFail(e) })?
    };
    server.run();
    Ok(())
}
