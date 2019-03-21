use quick_error::quick_error;

quick_error! {
    #[derive(Debug)]
    pub enum ClConfError {
        ConfigFileOpenFail(err: std::io::Error) {}
        ConfigFileReadFail(err: std::io::Error) {}
        TomlDesErr(err: toml::de::Error) { from() }
        InvalidAddress {}
        ParseListenAddress(err: std::net::AddrParseError) {}
        ParseListenPort(err: std::num::ParseIntError) {}
        NoApiKey {}
        NoApiSecret {}
        NoRedirectUri {}
        NoCommonApiKey {}
        NoListenAddrPort {}
        NoCookieSecretKey {}
        FailedToContructSealingKey {}
        FailedToContructOpeningKey {}
        InvalidDigestKeyBytesLen {}
        ParseAuthUri(err: actix_web::error::Error) {}
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum MainError {
        ClConfError(err: ClConfError) { from() }
        NoListenAddress {}
        NoListenPort {}
        NoTlsCertFileSpecified {}
        TlsCertFileOpenFail(err: std::io::Error) {}
        NoTlsKeyFileSpecified {}
        TlsKeyFileOpenFail(err: std::io::Error) {}
        BindAddrFail(e: std::io::Error) {}
        BindTlsAddrFail(e: std::io::Error) {}
        ShowConfigWriteFmtFail(e: std::io::Error) {}
    }
}
