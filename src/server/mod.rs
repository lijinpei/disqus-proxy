mod tls;

use crate::{ConfigFile, ApiConfig, error};

use actix_web::{App, server, client, HttpRequest, FutureResponse, HttpResponse, http, dev::{Resource, HttpResponseBuilder}, HttpMessage};
use actix_web::middleware::{identity::{IdentityService, CookieIdentityPolicy, RequestIdentity}, session::RequestSession};
use std::path::PathBuf;
use std::result::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use futures::future;
use std::boxed::Box;

fn get_listen_address(conf: &ConfigFile) -> Result<SocketAddr, error::MainError> {
    let listen_addr = conf.listen_address.clone().ok_or(error::MainError::NoListenAddress)?;
    let addr = listen_addr.parse::<std::net::Ipv4Addr>().map_err(|e| {error::MainError::ParseListenAddress(e)})?;
    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(addr, conf.listen_port.ok_or(error::MainError::NoListenPort)?))
}

#[derive(Deserialize)]
struct LoginInfo {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginInfoForm <'a>{
    username: &'a str,
    password: &'a str,
    csrfmiddlewaretoken: &'a str,
}

fn login_new_1(login_info: LoginInfo, token: String, session_id: String, prev_uri: String) -> impl future::Future<Item=HttpResponseBuilder, Error=actix_web::error::Error> {
    use future::{Future, IntoFuture};
    let uri = "https://disqus.com/api/oauth/2.0/grant/";
    let form = LoginInfoForm {
        username: &login_info.username,
        password: &login_info.password,
        csrfmiddlewaretoken: &token,
    };
    let cookie = format!("csrftoken={}; sessionid={}", token, session_id);
    client::post(&uri).no_default_headers().header("User-Agent", "curl/7.64.0").header("Cookie", cookie)
    //.header(actix_web::http::header::REFERER, prev_uri)
    //.set_header(actix_web::http::header::HOST, "disqus.com")
    .form(form).into_future().from_err().and_then(|res| {
        log::info!("login_new1_send_request {:?}", res);
        log::info!("login_new1_send_request body {:?}", res.body());
        res.send().map_err(|e| { log::info!("login_new_1_post_form_error {:?}", e); e }).from_err().and_then(|response| {
            log::info!("login_new_1_disqus_server_response_header {:?}", response.headers());
                return future::err(std::convert::Into::<actix_web::error::Error>::into(actix_web::middleware::csrf::CsrfError::CsrDenied));
            })})
}

fn login_new(req: HttpRequest<ApiConfig>) -> FutureResponse<HttpResponseBuilder> {
    use future::{Future, IntoFuture};
    Box::new(
        req.urlencoded::<LoginInfo>()
        .map_err(|e| { log::info!("login_new_urlencoded_error {:?}", e); actix_web::error::ErrorInternalServerError(e) })
        .and_then(move |login_info| {
            let conf = req.state();
            let uri = format!("https://disqus.com/api/oauth/2.0/authorize/?client_id={}&scope=read,write&response_type=code&redirect_uri={}", conf.api_key, conf.redirect_uri);
            client::get(&uri).finish().into_future().and_then(|res| {
                res.send().map_err(|e| { log::info!("login_new_urlencoded_send_error {:?}", e); actix_web::error::ErrorInternalServerError(e) }).and_then(|response| {
                    log::info!("login_new_disqus_server_response {:?}", response);
                    match response.cookies() {
                        Err(err) => {
                            return future::Either::A(future::err(actix_web::error::ErrorInternalServerError(err)));
                        },
                        Ok(cookies) => {
                            let mut token = None;
                            let mut session_id = None;
                            for cookie in cookies {
                                match cookie.name() {
                                    "csrftoken" => {
                                        token = Some(cookie.value().to_owned());
                                    },
                                    "sessionid" => {
                                        session_id = Some(cookie.value().to_owned());
                                    },
                                    name @ _ => {
                                        log::info!("login_new_disqus_response_unknown_cookie name {} value {}", name, cookie.value());
                                    }
                                }
                            }
                            match (token, session_id) {
                                (Some(token), Some(session_id)) => {
                                    let res = login_new_1(login_info, token, session_id, uri);
                                    return future::Either::B(future::Either::A(res));
                                },
                                _ => {
                                    let res = future::err(actix_web::error::ErrorInternalServerError(actix_web::middleware::csrf::CsrfError::CsrDenied));
                                    return future::Either::B(future::Either::B(res));
                                },
                            }
                        },
                    }
                })
            })
        })
    )
}

fn login(req: HttpRequest<ApiConfig>) -> FutureResponse<HttpResponseBuilder> {
    match req.identity() {
        Some(name) => {
            log::info!("login_name {}", name);
            return Box::new(future::FutureResult::from(Result::Ok(HttpResponse::Ok())));
        },
        None => {
            log::info!("login_none");
            return login_new(req);
        },
    }
}

fn logout(req: HttpRequest<ApiConfig>) -> HttpResponseBuilder {
    match req.identity() {
        Some(name) => {
            log::info!("logout_name {}", name);
            req.forget();
            return HttpResponse::Ok();
        },
        None => {
            log::info!("logout_none");
            return HttpResponse::NotFound();
        }
    }
}

fn build_app(conf: &ConfigFile, api_conf: &ApiConfig)-> App<ApiConfig> {
    let app = App::with_state(api_conf.to_owned())
    .middleware(actix_web::middleware::Logger::default())
    // TODO: make sure it is safe to use empty key
    .middleware(IdentityService::new(CookieIdentityPolicy::new(&[0; 256]).name("disqus-auth").secure(true)));
    let app = if let Some(ref v) = conf.path_prefix {
        app.prefix(v.clone())
    } else {
        app
    };
    app
    .route("/login", http::Method::POST, login)
    .route("/logout", http::Method::POST, logout)
}

pub(crate) fn run_server(_conf_path: Option<PathBuf>, conf_file: ConfigFile, api_conf: ApiConfig) -> Result<(), error::MainError>{
    let addr = get_listen_address(&conf_file)?;
    let conf_file = Arc::new(conf_file);
    let api_conf = Arc::new(api_conf);
    let server = 
    {
        let conf_file = conf_file.clone();
        let api_conf = api_conf.clone();
        server::new(move || {
            build_app(&conf_file, &api_conf)
        })
    };
    let server = if let Some(true) = conf_file.use_tls {
        let server_config = tls::load_tls(&conf_file)?;
        server.bind_rustls(addr, server_config).map_err(|e| { error::MainError::BindTlsAddrFail(e) })?
    } else {
        server.bind(addr).map_err(|e| { error::MainError::BindAddrFail(e) })?
    };
    server.run();
    Ok(())
}
