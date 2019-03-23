use quick_error::quick_error;

quick_error! {
    #[derive(Debug)]
    pub enum ProxyError {
        FailedToOpenFile(err: std::io::Error) {}
        FailedToReadFile(err: std::io::Error) {}
        FailedToDeserializeToml(err: toml::de::Error) {}
        /*
        TomlFirstLevelNotTable,
        TomlSecondLevelNotTable,
        TomlThirfLevelNotTable,
        */
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ProxyTomlConfigError {
        NoContentUnderPath(err: String) {}
        AuthMethodMissMatch {}
    }
}