use clap::load_yaml;
use serde::Deserialize;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::result::Result;

pub mod error;
pub mod server;

#[derive(Deserialize, Default, Debug, Clone)]
struct ConfigFile {
    api_key: Option<String>,
    api_secret: Option<String>,
    redirect_uri: Option<String>,
    common_api_key: Option<String>,

    addr_port: Option<String>,
    use_tls: Option<bool>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,

    path_prefix: Option<String>, // response only as the specified host
    cookie_secret_key: Option<String>,

    pg_user: Option<String>,
    pg_password: Option<String>,
    pg_dbname: Option<String>,
    pg_host: Option<String>,
    pg_port: Option<String>,
    pg_options: Option<String>,
}

enum ClCommand {
    RunServer,
    ShowConfig,
}

fn handle_config() -> Result<(ClCommand, Option<PathBuf>, ConfigFile), error::ClConfError> {
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
        config.addr_port = Some(v.to_string());
    }

    if matches.is_present("use_tls") {
        config.use_tls = Some(true);
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

    if let Some(v) = matches.value_of("pg_user") {
        config.pg_user = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("pg_password") {
        config.pg_password = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("pg_dbname") {
        config.pg_dbname = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("pg_host") {
        config.pg_host = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("pg_port") {
        config.pg_port = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("pg_options") {
        config.pg_options = Some(v.to_string());
    }

    let command = 
    if matches.is_present("show") {
        ClCommand::ShowConfig
    } else {
        ClCommand::RunServer
    };
    
    Ok((command, config_path, config))
}

fn show_config<OS: std::io::Write>(conf_file_path: Option<PathBuf>, conf_file: ConfigFile, os: &mut OS) -> Result<(), error::MainError> {
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
    Ok(())
}

fn lookup_command(cmd: ClCommand) -> impl FnOnce(Option<PathBuf>, ConfigFile) -> Result<(), error::MainError> {
    use ClCommand::*;
    fn show_config_1(conf_file_path: Option<PathBuf>, conf_file: ConfigFile) -> Result<(), error::MainError> {
        show_config(conf_file_path, conf_file, &mut std::io::stderr())
    }
    fn run_server_1(conf_file_path: Option<PathBuf>, conf_file: ConfigFile) -> Result<(), error::MainError> {
        log::info!("conf_file_path {:?}", conf_file_path);
        log::info!("conf_file {:?}", conf_file);
        server::run_server(conf_file_path, conf_file)
    }
    match cmd {
        RunServer => run_server_1,
        ShowConfig => show_config_1,
    }
}

fn main() -> Result<(), error::MainError> {
    env_logger::init();
    log::info!("disqus-proxy started");
    let (cmd, conf_file_path, conf_file) = handle_config()?;
    let cmd = lookup_command(cmd);
    let ret = cmd(conf_file_path, conf_file);
    log::info!("disqus-proxy finished");
    ret
}
