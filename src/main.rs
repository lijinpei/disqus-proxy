use clap::load_yaml;
use serde::Deserialize;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::result::Result;

pub mod error;
pub mod server;

#[derive(Deserialize, Default, Debug, Clone)]
struct Config {
    listen_address: Option<String>,
    listen_port: Option<u16>,
    api_key: Option<String>,
    api_secret: Option<String>,
    redirect_uri: Option<String>,
    use_tls: Option<bool>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    host_domain: Option<String>
}

enum ClCommand {
    RunServer,
    ShowConfig,
}

fn handle_command_line_and_config() -> Result<(ClCommand, Option<PathBuf>, Config), error::ClConfError> {
    use error::ClConfError;
    use std::io::Read;

    let yaml = load_yaml!("cli.yml");
    let matches = clap::App::from_yaml(yaml).get_matches();
    let mut config;
    let config_path;

    fn load_config_from_path(path: &Path) -> Result<Config, ClConfError> {
        let mut res = File::open(path).map_err(|e| {error::ClConfError::ConfigFileOpenFail(e)})?;
        let mut contents = String::new();
        let res = res.read_to_string(&mut contents).map_err(|e| { error::ClConfError::ConfigFileReadFail(e) })?;
        let conf = toml::from_str(&contents)?;
        Ok(conf)
    }

    if let Some(path) = matches.value_of("config") {
        let path = std::path::Path::new(path);
        config = load_config_from_path(path)?;
        config_path = Some(path.to_owned());
    } else {
        if matches.is_present("no_default_config") {
            config_path = None;
            config = Config::default();
        } else {
            let path = std::path::Path::new("disqus_proxy.toml");
            config = load_config_from_path(path)?;
            config_path = Some(path.to_owned());
        }
    };

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

    if let Some(v) = matches.value_of("host_domain") {
        config.host_domain = Some(v.to_string());
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

    if let Some(v) = matches.value_of("api_key") {
        config.api_key = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("api_secret") {
        config.api_secret = Some(v.to_string());
    }
    if let Some(v) = matches.value_of("redirect_uri") {
        config.redirect_uri = Some(v.to_string());
    }

    let command = 
    if matches.is_present("show") {
        ClCommand::ShowConfig
    } else {
        ClCommand::RunServer
    };
    return Ok((command, config_path, config));

}

fn show_config(conf_path: Option<PathBuf>, conf: Config) -> Result<(), error::MainError> {
    match conf_path {
        Some(path) => {
            eprintln!("load config from path {:?}", path);
        },
        None => {
            eprintln!("didn't load config form file");
        },
    };
    eprintln!("{:?}", conf);
    Ok(())
}

fn main() -> Result<(), error::MainError> {
    let (cmd, conf_path, conf) = handle_command_line_and_config()?;
    match cmd {
        ClCommand::RunServer => {
            server::run_server(conf_path, conf)
        },
        ClCommand::ShowConfig => {
            show_config(conf_path, conf)
        },
    }
}
