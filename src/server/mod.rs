mod tls;

use crate::{ConfigFile, error};

//use tokio_postgres as pg;
use actix_web::{App, client as http_client, http, HttpRequest, HttpResponse, FutureResponse};
use std::path::PathBuf;
use std::result::Result;
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use futures::future;
use std::boxed::Box;

// trait usage
use actix_web::HttpMessage;
use future::{Future, IntoFuture};
use actix_web::middleware::identity::RequestIdentity;

#[derive(Clone)]
struct ApiConfig {
    api_key: String,
    api_secret: String,
    redirect_uri: String,
    common_api_key: String,

    auth_uri: String,
}

impl ApiConfig {
    pub fn from_conf_file(conf_file: &ConfigFile) -> Result<ApiConfig, error::ClConfError> {
        use error::ClConfError::*;
        // ensure evaluation order
        let api_key = conf_file.api_key.clone().ok_or(NoApiKey)?;
        let api_secret = conf_file.api_secret.clone().ok_or(NoApiSecret)?;
        let redirect_uri = conf_file.redirect_uri.clone().ok_or(NoRedirectUri)?;
        let common_api_key = conf_file.common_api_key.clone().ok_or(NoCommonApiKey)?;
        let auth_uri = format!("https://disqus.com/api/oauth/2.0/authorize/?client_id={}&scope=read,write&response_type=code&redirect_uri={}", api_key, redirect_uri);
        Ok(ApiConfig {
            api_key,
            api_secret,
            redirect_uri,
            common_api_key,
            auth_uri
        })
    }
}

#[derive(Clone)]
struct AppState {
    api_conf: ApiConfig,
//    pg_client: pg::Client,
}

impl AppState {
    pub fn from_conf_file(conf_file: &ConfigFile) -> Result<AppState, error::ClConfError> {
        Ok( AppState {
            api_conf: ApiConfig::from_conf_file(conf_file)?
        })
    }
}

fn get_listen_address(conf: &ConfigFile) -> Result<SocketAddr, error::ClConfError> {
    let addr_port = conf.addr_port.clone().ok_or(error::ClConfError::NoListenAddrPort)?;
    let pos = addr_port.rfind(':').ok_or(error::ClConfError::InvalidAddress)?;
    if pos == 0 {
        return Err(error::ClConfError::InvalidAddress);
    }
    let port = addr_port[pos + 1..].parse().map_err(|e| { error::ClConfError::ParseListenPort(e) })?;
    use std::net::*;
    let addr = addr_port[..pos].parse::<Ipv4Addr>().map_err(|e| {error::ClConfError::ParseListenAddress(e)})?;
    Ok(SocketAddr::V4(SocketAddrV4::new(addr, port))
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

#[derive(Serialize)]
struct GrantInfo<'a> {
    grant_type: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    redirect_uri: &'a str,
    code: &'a str,
}

fn login_new_grant(code: &[u8], state: AppState) -> impl future::Future<Item=HttpResponse, Error=actix_web::error::Error> {
    log::info!("login_new_grant");
    let grant_info = GrantInfo {
        grant_type: "authorization_code",
        client_id: &state.api_conf.api_key,
        client_secret: &state.api_conf.api_secret,
        redirect_uri: &state.api_conf.redirect_uri,
        code: unsafe { std::str::from_utf8_unchecked(code) }
    };
    let grant_uri = "https://disqus.com/api/oauth/2.0/access_token/";
    let mut req = http_client::post(&grant_uri);
    req.header(actix_web::http::header::HOST, "disqus.com");
    let req = req.form(grant_info);
    log::info!("login_new_grant_send_request {:?}", req);
    req.into_future().map_err(|e| {log::info!("login_new_grant_form_post_error {:?}", e); actix_web::error::ErrorInternalServerError(e)}).and_then(|res| {
        res.send().map_err(|e| { log::info!("login_new_grant_send_post_error {:?}", e); actix_web::error::ErrorInternalServerError(e)}).and_then(move |response| {
            log::info!("login_new_grant_disqus_response {:?}", response);
            response.body().and_then(|res| {
            log::info!("login_new_grant_disqus_response body{:?}", res);
            future::ok(HttpResponse::Ok().finish())
            }).map_err(|e| {actix_web::error::ErrorInternalServerError(e) })
        })
    })
}

// 'a is the life time of the request
fn login_new_auth<'a>(login_info: LoginInfo, token: String, session_id: String, state: AppState) -> impl future::Future<Item=HttpResponse, Error=actix_web::error::Error> + 'a {
    log::info!("inside login new auth");
    use future::{Future, IntoFuture};
    let form = LoginInfoForm {
        username: &login_info.username,
        password: &login_info.password,
        csrfmiddlewaretoken: &token,
    };
    let cookie = format!("csrftoken={}; sessionid={}", token, session_id);
    let auth_uri = "https://disqus.com/api/oauth/2.0/grant/";
    http_client::post(&auth_uri).header("Cookie", cookie)
    .header(actix_web::http::header::REFERER, auth_uri)
    .header(actix_web::http::header::HOST, "disqus.com")
    .form(form).into_future().map_err(|e| { log::info!("login_new_auth_form_post_error {:?}", e); e }).from_err().and_then(|res| {
        log::info!("login_new1_send_request {:?}", res);
        log::info!("login_new1_send_request body {:?}", res.body());
        res.send().map_err(|e| { log::info!("login_new_1_post_form_error {:?}", e); e }).from_err().and_then(move |response| {
            log::info!("login_new_1_disqus_server_response_header {:?}", response.headers());
            if response.status() == http::StatusCode::FOUND {
                if let Some(redirect_uri) = response.headers().get("location") {
                    let redirect_uri = redirect_uri.as_bytes();
                    let len = state.api_conf.redirect_uri.len();
                    let suffix = "?code=";
                    let suffix_len = suffix.len();
                    if redirect_uri.len() > len + suffix_len && &redirect_uri[0..len] == state.api_conf.redirect_uri.as_bytes() && &redirect_uri[len..len+suffix_len] == suffix.as_bytes() {
                        let code = &redirect_uri[len+suffix_len..];
                        log::info!("login_new_auth_get_code {:?}", std::str::from_utf8(&code));
                        return future::Either::A(login_new_grant(code, state));
                    }
                }
            }
            return future::Either::B(future::err(std::convert::Into::<actix_web::error::Error>::into(actix_web::middleware::csrf::CsrfError::CsrDenied)));
        })
    })
}

fn login_new(req: HttpRequest<AppState>) -> FutureResponse<HttpResponse> {
    use future::{Future, IntoFuture};
    Box::new(
        req.urlencoded::<LoginInfo>()
        .map_err(|e| { log::info!("login_new_urlencoded_error {:?}", e); actix_web::error::ErrorInternalServerError(e) })
        .and_then(move |login_info| {
            let state = req.state().clone();
            http_client::get(&state.api_conf.auth_uri).finish().into_future().and_then(|res| {
                res.send().map_err(|e| { log::info!("login_new_urlencoded_send_error {:?}", e); actix_web::error::ErrorInternalServerError(e) })
                .and_then(move |response| {
                    log::info!("login_new_disqus_server_response {:?}", response);
                    // TODO: make this zero copy?
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
                                    let res = login_new_auth(login_info, token, session_id, state);
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

fn login(req: HttpRequest<AppState>) -> FutureResponse<HttpResponse> {
    match req.identity() {
        Some(name) => {
            log::info!("login_name {}", name);
            return Box::new(future::ok(HttpResponse::Ok().finish()));
        },
        None => {
            log::info!("login_none");
            return login_new(req);
        },
    }
}

fn logout(req: HttpRequest<AppState>) -> HttpResponse {
    match req.identity() {
        Some(name) => {
            log::info!("logout_name {}", name);
            req.forget();
            return HttpResponse::Ok().finish();
        },
        None => {
            log::info!("logout_none");
            return HttpResponse::NotFound().finish();
        }
    }
}

fn build_app(path_prefix: &Option<String>, app_state: AppState)-> App<AppState> {
    App::with_state(app_state)
    .middleware(actix_web::middleware::Logger::default())
    .configure(move |app| {
        if let Some(ref v) = path_prefix {
            app.prefix(v.clone())
        } else {
            app
        }
    })
    .route("/login", http::Method::POST, login)
    .route("/logout", http::Method::POST, logout)
}

pub(crate) fn run_server(_conf_path: Option<PathBuf>, conf_file: ConfigFile) -> Result<(), error::MainError>{
    let server = 
    {
        let app_state = AppState::from_conf_file(&conf_file)?;
        let path_prefix = conf_file.path_prefix.clone();
        actix_web::server::new(move || {
            build_app(&path_prefix, app_state.clone())
        })
    };
    let addr = get_listen_address(&conf_file)?;
    log::info!("run_server_prepare_to_bind {}", addr);
    let server = if let Some(true) = conf_file.use_tls {
        let server_config = tls::load_tls(&conf_file)?;
        server.bind_rustls(addr, server_config).map_err(|e| { error::MainError::BindTlsAddrFail(e) })?
    } else {
        server.bind(addr).map_err(|e| { error::MainError::BindAddrFail(e) })?
    };
    server.run();
    Ok(())
}
