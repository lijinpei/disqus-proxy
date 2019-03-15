use clap::load_yaml;
use serde::Deserialize;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::result::Result;

pub mod error;
pub mod server;

#[derive(Deserialize, Default, Debug, Clone)]
struct ApiConfig {
    api_key: String,
    api_secret: String,
    redirect_uri: String,
    common_api_key: String,
}

#[derive(Deserialize, Default, Debug, Clone)]
struct ConfigFile {
    api_key: Option<String>,
    api_secret: Option<String>,
    redirect_uri: Option<String>,
    common_api_key: Option<String>,

    listen_address: Option<String>,
    listen_port: Option<u16>,
    use_tls: Option<bool>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,

    path_prefix: Option<String>, // response only as the specified host
}

enum ClCommand {
    RunServer,
    ShowConfig,
}

fn get_api_conf(conf_file: &ConfigFile) -> Result<ApiConfig, error::ClConfError> {
    use error::ClConfError::*;
    Ok(ApiConfig {
        api_key: conf_file.api_key.clone().ok_or(NoApiKey)?,
        api_secret: conf_file.api_secret.clone().ok_or(NoApiSecret)?,
        redirect_uri: conf_file.redirect_uri.clone().ok_or(NoRedirectUri)?,
        common_api_key: conf_file.common_api_key.clone().ok_or(NoCommonApiKey)?,
    })
}

fn handle_config() -> Result<(ClCommand, Option<PathBuf>, ConfigFile, ApiConfig), error::ClConfError> {
    use error::ClConfError;
    use std::io::Read;

    let yaml = load_yaml!("cli.yml");
    let matches = clap::App::from_yaml(yaml).get_matches();
    let mut config;
    let config_path;

    fn load_config_from_path(path: &Path) -> Result<ConfigFile, ClConfError> {
        let mut res = File::open(path).map_err(|e| {error::ClConfError::ConfigFileOpenFail(e)})?;
        let mut contents = String::new();
        let res = res.read_to_string(&mut contents).map_err(|e| { error::ClConfError::ConfigFileReadFail(e) })?;
        let conf_file = toml::from_str(&contents)?;
        Ok(conf_file)
    }

    if let Some(path) = matches.value_of("config") {
        let path = std::path::Path::new(path);
        config = load_config_from_path(path)?;
        config_path = Some(path.to_owned());
    } else {
        if matches.is_present("no_default_config") {
            config_path = None;
            config = ConfigFile::default();
        } else {
            let path = std::path::Path::new("disqus_proxy.toml");
            config = load_config_from_path(path)?;
            config_path = Some(path.to_owned());
        }
    };

    if let Some(v) = matches.value_of("api_key") {
        config.api_key = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("api_secret") {
        config.api_secret = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("redirect_uri") {
        config.redirect_uri = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("common_api_key") {
        config.common_api_key= Some(v.to_string());
    }
    if config.common_api_key == None {
        config.common_api_key= Some("E8Uh5l5fHZ6gD8U3KycjAIAk46f68Zw7C6eW8WSjZvCLXebZ7p0r1yrYDrLilk2F".to_string());
    }

    if let Some(v) = matches.value_of("addr_port") {
        let pos = v.rfind(':');
        if pos.is_none() {
            return Err(error::ClConfError::InvalidAddress);
        };
        let pos = pos.unwrap();
        let (addr, port) = v.split_at(pos + 1);
        let len = addr.len();
        if len == 0 {
            return Err(error::ClConfError::InvalidAddress);
        }
        config.listen_address = Some(addr[..len-1].to_string());
        config.listen_port = Some(port.parse()?);
    }

    if let Some(v) = matches.value_of("use_tls") {
        config.use_tls = Some(v.parse()?);
    }

    if let Some(true) = config.use_tls {
        if let Some(v) = matches.value_of("tls_cert") {
            config.tls_cert = Some(PathBuf::from(v));
        }
        if let Some(v) = matches.value_of("tls_key") {
            config.tls_key = Some(PathBuf::from(v));
        }
    }

    if let Some(v) = matches.value_of("path_prefix") {
        config.path_prefix = Some(v.to_string());
    }

    let api_conf = get_api_conf(&config)?;

    let command = 
    if matches.is_present("show") {
        ClCommand::ShowConfig
    } else {
        ClCommand::RunServer
    };
    
    Ok((command, config_path, config, api_conf))
}

fn show_config<OS: std::io::Write>(conf_file_path: Option<PathBuf>, conf_file: ConfigFile, api_conf: ApiConfig, os: &mut OS) -> Result<(), error::MainError> {
    macro_rules! my_println {
        ($($e:expr),*) => { os.write_fmt(format_args!($($e),*)).map_err(|e| { error::MainError::ShowConfigWriteFmtFail(e)})? }
    }
    match conf_file_path {
        Some(path) => {
            my_println!("load config file from path {:?}", path);
        },
        None => {
            my_println!("didn't load config file");
        },
    };
    my_println!("{:?}", conf_file);
    my_println!("{:?}", api_conf);
    Ok(())
}

fn lookup_command(cmd: ClCommand) -> impl FnOnce(Option<PathBuf>, ConfigFile, ApiConfig) -> Result<(), error::MainError> {
    use ClCommand::*;
    fn show_config_1(conf_file_path: Option<PathBuf>, conf_file: ConfigFile, api_conf: ApiConfig) -> Result<(), error::MainError> {
        show_config(conf_file_path, conf_file, api_conf, &mut std::io::stderr())
    }
    fn run_server_1(conf_file_path: Option<PathBuf>, conf_file: ConfigFile, api_conf: ApiConfig) -> Result<(), error::MainError> {
        log::info!("conf_file_path {:?}", conf_file_path);
        log::info!("conf_file {:?}", conf_file);
        log::info!("api_conf {:?}", api_conf);
        server::run_server(conf_file_path, conf_file, api_conf)
    }
    match cmd {
        RunServer => run_server_1,
        ShowConfig => show_config_1,
    }
}

fn main() -> Result<(), error::MainError> {
    env_logger::init();
    log::info!("disqus-proxy started");
    let (cmd, conf_file_path, conf_file, api_conf) = handle_config()?;
    let cmd = lookup_command(cmd);
    let ret = cmd(conf_file_path, conf_file, api_conf);
    log::info!("disqus-proxy finished");
    ret
}
