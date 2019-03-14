use quick_error::quick_error;

quick_error! {
    #[derive(Debug)]
    pub enum ClConfError {
        ConfigFileOpenFail(err: std::io::Error) {
        }
        ConfigFileReadFail(err: std::io::Error) {
        }
        TomlDesErr(err: toml::de::Error) {
            from()
        }
        InvalidAddress {}
        ParsePortErr(err: std::num::ParseIntError) {
            from()
        }
        ParseUseTlsErr(err: std::str::ParseBoolError) {
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum MainError {
        ClConfError(err: ClConfError) { from()}
        NoListenAddress {}
        NoListenPort {}
        ParseListenAddress(err: std::net::AddrParseError) {}
        NoTlsCertFileSpecified {}
        TlsCertFileOpenFail(err: std::io::Error) {}
        NoTlsKeyFileSpecified {}
        TlsKeyFileOpenFail(err: std::io::Error) {}
        BindAddrFail(e: std::io::Error) {}
        BindTlsAddrFail(e: std::io::Error) {}
    }
}
