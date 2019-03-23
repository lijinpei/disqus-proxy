pub mod error;
use serde::Deserialize;
use error::{ProxyError, ProxyTomlConfigError};
use std::path::Path;

#[derive(Deserialize, PartialEq, Eq)]
enum ServerSideAuth {
    None,
    ServerPublicKey,
    ServerPrivateKey,
    CommonPublicKey,
    ClientToken,
}

#[derive(Deserialize, PartialEq, Eq)]
enum ClientSideAuth {
    None,
    ClientToken,
}

#[derive(Deserialize)]
enum HttpMethod {
    Get,
    Post
}

#[derive(Deserialize)]
struct ApiInfo {
    method: HttpMethod,
    server_auth: ServerSideAuth,
    client_auth: ClientSideAuth,
}

impl ApiInfo {
    pub fn sanity_check(&self) -> Result<(), ProxyTomlConfigError> {
        match self.server_auth {
            /*
            None => {
            },
            ServerPublicKey => {
            },
            ServerPrivateKey => {
            },
            CommonPublicKey => {
            },
            */
            ServerSideAuth::ClientToken => {
                if self.client_auth != ClientSideAuth::ClientToken {
                    return Err(ProxyTomlConfigError::AuthMethodMissMatch);
                } else {
                    return Ok(());
                }
            },
            _ => {
                return Ok(());
            }
        }
    }
}

#[derive(Deserialize)]
struct ProxyInfo {
    path: String,
    api: Option<ApiInfo>,
    subs: Option<Vec<ProxyInfo>>,
}

impl ProxyInfo {
    pub fn from_toml_file(path: &Path) -> Result<Vec<Self>, ProxyError> {
        let mut f = std::fs::File::open(path).map_err(|e| {ProxyError::FailedToOpenFile(e) })?;
        let mut contents = String::new();
        Ok(toml::from_str(&contents).map_err(|e| {ProxyError::FailedToDeserializeToml(e)})?) 
        //from_toml_value(val);
    }

    pub fn sanity_check(&self, parent_path: &str) -> Result<(), ProxyTomlConfigError> {
        // FIXME: how to check valid path
        if self.api.is_none() && self.subs.is_none() {
            return Err(ProxyTomlConfigError::NoContentUnderPath(parent_path.to_string() + &self.path));
        }
        if let Some(api) = &self.api {
            api.sanity_check()?;
        }
        if let Some(vec) = &self.subs {
            let path = parent_path.to_string() + &self.path + "/";
            for p in vec {
                p.sanity_check(&path)?;
            }
        }
        Ok(())
    }
/*
    pub fn from_toml_value(val: toml::value::Value) -> Result<Vec<Self>, ProxyError> {
        use toml::value::Value;
        match val {
            Value::Table(tab) => {
                let mut ret = Vec::new();
                for (p1, v) in tab {
                    match v {
                        Value::Table(tab) => {
                            for (p2, v) in tab {
                                match v {
                                    Value::Table(v) => {
                                        ret.push(get_info(p1, p2, v)?);
                                    },
                                    _ => {
                                        return Err(ProxyError::TomlThirdLevelNotTable);
                                    }
                                }
                            }
                        },
                        _ => {
                            return Err(ProxyError::TomlSecondLevelNotTable);
                        }
                    }
                }
                return Ok(ret);
            },
            _ => {
                return Err(ProxyError::TomlFirstLevelNotTable)
            }
        }
    }

    fn get_info(p1: &str, p2: &str, val: toml::Value::Table) -> Result<ProxyInfo, ProxyError> {
        let (p1, p2) = 
        if let Some(path) = val.get("path") {

        } else {
            (p1.to_string(), p2.to_string())
        }
    }
*/
}