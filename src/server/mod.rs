mod tls;

use crate::{Config, error};

use actix_web::{App, server, client, HttpRequest, FutureResponse, HttpResponse, http, dev::{Resource, HttpResponseBuilder}, HttpMessage};
use actix_web::middleware::{identity::{IdentityService, CookieIdentityPolicy, RequestIdentity}, session::RequestSession};
use std::path::PathBuf;
use std::result::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use serde::Deserialize;
use futures::future::{Future, FutureResult};
use std::boxed::Box;

fn get_addr(conf: &Config) -> Result<SocketAddr, error::MainError> {
    let listen_addr = conf.listen_address.clone().ok_or(error::MainError::NoListenAddress)?;
    let addr = listen_addr.parse::<std::net::Ipv4Addr>().map_err(|e| {error::MainError::ParseListenAddress(e)})?;
    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(addr, conf.listen_port.ok_or(error::MainError::NoListenPort)?))
}

#[derive(Deserialize)]
struct LoginInfo {
    username: String,
    password: String,
}

fn login_new(req: HttpRequest<Config>) -> FutureResponse<HttpResponse> {
    Box::new(
        req.urlencoded::<LoginInfo>()
        .map_err(|e| { eprintln!("deserialize error {:?}", e); e })
        .from_err()
        .and_then(move |login_info| {
            let conf = req.state().clone();
            let uri = format!("https://disqus.com/api/oauth/2.0/authorize/?client_id={}&scope=read,write&response_type=code&redirect_uri={}", conf.api_key.clone().unwrap(), conf.redirect_uri.clone().unwrap());
            client::get(&uri).finish().unwrap().send().from_err().and_then(|response| {
                eprintln!("response {:?}", response);
                response.body().limit(4096000).map_err(|e| { eprintln!("response error {}", e); e ).from_err().and_then(|msg| {
                    eprintln!("response body {:?}", msg);
                    Ok(HttpResponse::Ok().into())
                })
            })
            }))
}

fn login(req: HttpRequest<Config>) -> FutureResponse<HttpResponse> {
    match req.identity() {
        Some(_) => {
            eprintln!("login name");
            return Box::new(FutureResult::from(Result::Ok(HttpResponse::Ok().finish())));
        },
        None => {
            eprintln!("login none");
            return login_new(req);
        },
    }
}

fn logout(req: HttpRequest<Config>) -> HttpResponseBuilder {
    match req.identity() {
        Some(name) => {
            eprintln!("logout name {}", name);
            req.forget();
            return HttpResponse::Ok();
        },
        None => {
            eprintln!("logout none");
            return HttpResponse::NotFound();
        }
    }
}

// TODO: return a Result here
fn build_app(mut conf: Arc<Config>)-> App<Config> {
    App::with_state(Arc::make_mut(&mut conf).to_owned())
    .middleware(actix_web::middleware::Logger::default())
    .middleware(IdentityService::new(CookieIdentityPolicy::new(&[0; 256]).name("disqus-auth").secure(true),))
    .route("/login", http::Method::POST, login)
    .route("/logout", http::Method::POST, logout)
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
