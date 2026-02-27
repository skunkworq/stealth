use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::raw::c_char;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct TLSClientHello {
    pub raw_version: u16,
    pub raw_cipher_suites: Vec<u16>,
    pub raw_extensions: Vec<u16>,
    pub server_name: String,
    pub alpn_protocols: Vec<String>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub greases: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub key_share: Option<KeyShareEntry>,
    pub psk_key_exchange_modes: Vec<u8>,
    pub record_size_limit: Option<u16>,
    pub transport_parameters: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct KeyShareEntry {
    pub group: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TLSFingerprintResult {
    // Raw data
    pub timestamp_ms: u64,
    pub server_ip: String,
    pub server_port: u16,
    pub server_name: String,
    
    // Version info
    pub tls_version: String,
    pub tls_version_raw: u16,
    
    // JA3
    pub ja3_string: String,
    pub ja3_hash: String,
    
    // JA4
    pub ja4: String,
    pub ja4_short: String,
    
    // Cipher suites
    pub cipher_suites: Vec<String>,
    pub cipher_suite_count: usize,
    pub greases_in_ciphers: Vec<u16>,
    
    // Extensions
    pub extensions: Vec<String>,
    pub extension_count: usize,
    pub greases_in_extensions: Vec<u16>,
    
    // Key exchange
    pub supported_groups: Vec<String>,
    pub key_share_groups: Vec<String>,
    pub signature_algorithms: Vec<String>,
    
    // ALPN
    pub alpn: String,
    pub has_http2: bool,
    
    // GREASE
    pub has_grease: bool,
    pub grease_values: Vec<u16>,
    
    // Server name
    pub sni: String,
    pub sni_present: bool,
    
    // Additional
    pub supported_versions_tls13: bool,
    pub early_data_supported: bool,
    pub padding_present: bool,
    pub cookie_present: bool,
    
    // Detection
    pub detected_browser: String,
    pub fingerprint_anomalies: Vec<String>,
    pub trace_id: String,
}

impl Default for TLSFingerprintResult {
    fn default() -> Self {
        TLSFingerprintResult {
            timestamp_ms: 0,
            server_ip: String::new(),
            server_port: 0,
            server_name: String::new(),
            tls_version: String::new(),
            tls_version_raw: 0,
            ja3_string: String::new(),
            ja3_hash: String::new(),
            ja4: String::new(),
            ja4_short: String::new(),
            cipher_suites: Vec::new(),
            cipher_suite_count: 0,
            greases_in_ciphers: Vec::new(),
            extensions: Vec::new(),
            extension_count: 0,
            greases_in_extensions: Vec::new(),
            supported_groups: Vec::new(),
            key_share_groups: Vec::new(),
            signature_algorithms: Vec::new(),
            alpn: String::new(),
            has_http2: false,
            has_grease: false,
            grease_values: Vec::new(),
            sni: String::new(),
            sni_present: false,
            supported_versions_tls13: false,
            early_data_supported: false,
            padding_present: false,
            cookie_present: false,
            detected_browser: String::new(),
            fingerprint_anomalies: Vec::new(),
            trace_id: String::new(),
        }
    }
}

fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a
}

fn get_grease_name(val: u16) -> String {
    if !is_grease(val) {
        return format!("0x{:04x}", val);
    }
    let names: HashMap<u16, &str> = [
        (0x0a0a, "GREASE_0A0A"),
        (0x1a1a, "GREASE_1A1A"),
        (0x2a2a, "GREASE_2A2A"),
        (0x3a3a, "GREASE_3A3A"),
        (0x4a4a, "GREASE_4A4A"),
        (0x5a5a, "GREASE_5A5A"),
        (0x6a6a, "GREASE_6A6A"),
        (0x7a7a, "GREASE_7A7A"),
        (0x8a8a, "GREASE_8A8A"),
        (0x9a9a, "GREASE_9A9A"),
        (0xaaaa, "GREASE_AAAA"),
        (0xbaba, "GREASE_BABA"),
        (0xcaca, "GREASE_CACA"),
        (0xdada, "GREASE_DADA"),
        (0xeaea, "GREASE_EAEA"),
        (0xfafa, "GREASE_FAFA"),
    ].iter().cloned().collect();
    names.get(&val).map(|s| s.to_string()).unwrap_or_else(|| format!("GREASE_{:04X}", val))
}

fn get_cipher_name(val: u16) -> String {
    let names: HashMap<u16, &str> = [
        (0x0000, "TLS_NULL_WITH_NULL_NULL"),
        (0x0001, "TLS_RSA_WITH_NULL_MD5"),
        (0x0002, "TLS_RSA_WITH_NULL_SHA"),
        (0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
        (0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
        (0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
        (0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
        (0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA"),
        (0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
        (0x0009, "TLS_RSA_WITH_DES_CBC_SHA"),
        (0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
        (0x0016, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
        (0x0017, "TLS_DHE_DSS_WITH_DES_CBC_SHA"),
        (0x0018, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
        (0x0019, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
        (0x001a, "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
        (0x001b, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
        (0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
        (0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
        (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
        (0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
        (0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
        (0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
        (0x003e, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"),
        (0x003f, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
        (0x0040, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"),
        (0x0041, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
        (0x0067, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
        (0x006b, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
        (0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
        (0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
        (0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
        (0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
        (0x00a0, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
        (0x00a1, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
        (0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
        (0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
        (0x00a4, "TLS_DHE_RSA_WITH_AES_128_CCM"),
        (0x00a5, "TLS_DHE_RSA_WITH_AES_256_CCM"),
        (0x00a6, "TLS_DHE_RSA_WITH_AES_128_CCM_SHA256"),
        (0x00a7, "TLS_DHE_RSA_WITH_AES_256_CCM_SHA384"),
        (0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"),
        (0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"),
        (0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
        (0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"),
        (0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"),
        (0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
        (0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
        (0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
        (0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
        (0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
        (0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA"),
        (0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA"),
        (0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
        (0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"),
        (0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"),
        (0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
        (0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
        (0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
        (0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
        (0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
        (0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
        (0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
        (0xc025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"),
        (0xc026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"),
        (0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
        (0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
        (0xc029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"),
        (0xc02a, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"),
        (0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        (0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        (0xc02d, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"),
        (0xc02e, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"),
        (0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        (0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        (0xc031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"),
        (0xc032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"),
        (0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0x1301, "TLS_AES_128_GCM_SHA256"),
        (0x1302, "TLS_AES_256_GCM_SHA384"),
        (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
        (0x1304, "TLS_AES_128_CCM_SHA256"),
        (0x1305, "TLS_AES_128_CCM_8_SHA256"),
    ].iter().cloned().collect();
    names.get(&val).map(|s| s.to_string()).unwrap_or_else(|| format!("0x{:04x}", val))
}

fn get_extension_name(val: u16) -> String {
    let names: HashMap<u16, &str> = [
        (0x0000, "server_name"),
        (0x0001, "max_fragment_length"),
        (0x0002, "client_certificate_url"),
        (0x0003, "trusted_ca_keys"),
        (0x0004, "truncated_hmac"),
        (0x0005, "status_request"),
        (0x0006, "user_mapping"),
        (0x0007, "client_authz"),
        (0x0008, "server_authz"),
        (0x0009, "cert_type"),
        (0x000a, "supported_groups"),
        (0x000b, "ec_point_formats"),
        (0x000c, "srp"),
        (0x000d, "signature_algorithms"),
        (0x000e, "use_srtp"),
        (0x000f, "heartbeat"),
        (0x0010, "application_layer_protocol_negotiation"),
        (0x0011, "status_request_v2"),
        (0x0012, "signed_certificate_timestamp"),
        (0x0013, "client_certificate_type"),
        (0x0014, "server_certificate_type"),
        (0x0015, "padding"),
        (0x0016, "encrypt_then_mac"),
        (0x0017, "extended_master_secret"),
        (0x0018, "token_binding"),
        (0x0019, "cached_info"),
        (0x001a, "compress_certificate"),
        (0x001b, "record_size_limit"),
        (0x001c, "pwd_protect"),
        (0x001d, "pwd_clear"),
        (0x001e, "password_salt"),
        (0x001f, "token_binding"),
        (0x0020, "session_ticket"),
        (0x0021, "TLMSP"),
        (0x0022, "TLMSP_proxy"),
        (0x0023, "renegotiation_info"),
        (0x0024, "supported_ekt_ciphers"),
        (0x0025, "guests"),
        (0x0026, "psk_key_exchange_modes"),
        (0x0027, "certificate_authorities"),
        (0x0028, "oid_filters"),
        (0x0029, "post_handshake_auth"),
        (0x002a, "signature_algorithms_cert"),
        (0x002b, "key_share"),
        (0x002c, "path_length"),
        (0x002d, "user_mapping"),
        (0x002e, "endpoint_compatibility"),
        (0x002f, "supported_versions"),
        (0x0030, "cookie"),
        (0x0031, "psk_key_exchange_modes"),
        (0x0032, "certificate_compression"),
        (0x0033, "application_settings"),
        (0x0034, "early_data"),
        (0x0035, "cookie"),
        (0x0036, "psk_key_exchange_modes"),
        (0x0037, "certificate_authorities"),
        (0x0038, "oid_filters"),
        (0x0039, "post_handshake_auth"),
        (0x003a, "signature_algorithms_cert"),
        (0x003b, "key_share"),
        (0x003c, "max_early_data_size"),
        (0x003d, "early_data"),
        (0x003e, "cookie"),
        (0x003f, "psk_key_exchange_modes"),
        (0x0040, "certificate_authorities"),
        (0x0041, "oid_filters"),
        (0x0050, "quic_transport_parameters"),
        (0x0055, "channel_idx0056"),
        (0, "duplicate_extension"),
        (0x006b, "supported_ecc_curves"),
        (0x006d, "application_settings"),
        (0xff01, "padding"),
    ].iter().cloned().collect();
    names.get(&val).map(|s| s.to_string()).unwrap_or_else(|| {
        if is_grease(val) {
            get_grease_name(val)
        } else {
            format!("0x{:04x}", val)
        }
    })
}

fn get_group_name(val: u16) -> String {
    let names: HashMap<u16, &str> = [
        (0x0017, "secp256r1"),
        (0x0018, "secp384r1"),
        (0x0019, "secp521r1"),
        (0x001d, "x25519"),
        (0x001e, "x448"),
        (0x0100, "ffdhe2048"),
        (0x0101, "ffdhe3072"),
        (0x0102, "ffdhe4096"),
        (0x0103, "ffdhe6144"),
        (0x0104, "ffdhe8192"),
    ].iter().cloned().collect();
    names.get(&val).map(|s| s.to_string()).unwrap_or_else(|| format!("0x{:04x}", val))
}

fn get_signature_name(val: u16) -> String {
    let names: HashMap<u16, &str> = [
        (0x0201, "ecdsa_secp256r1_sha256"),
        (0x0203, "ecdsa_secp384r1_sha384"),
        (0x0205, "ecdsa_secp521r1_sha512"),
        (0x0401, "rsa_pkcs1_sha256"),
        (0x0403, "rsa_pkcs1_sha384"),
        (0x0405, "rsa_pkcs1_sha512"),
        (0x0501, "rsa_pkcs1_sha224"),
        (0x0503, "ecdsa_sha224"),
        (0x0804, "rsa_pss_pss_sha256"),
        (0x0805, "rsa_pss_pss_sha384"),
        (0x0806, "rsa_pss_pss_sha512"),
        (0x0807, "rsa_pss_rsae_sha256"),
        (0x0808, "rsa_pss_rsae_sha384"),
        (0x0809, "rsa_pss_rsae_sha512"),
    ].iter().cloned().collect();
    names.get(&val).map(|s| s.to_string()).unwrap_or_else(|| format!("0x{:04x}", val))
}

fn parse_client_hello(data: &[u8]) -> Option<TLSClientHello> {
    if data.len() < 43 {
        return None;
    }
    
    let mut offset = 0;
    
    // Skip TLS record header
    offset += 5;
    
    // Skip handshake header
    offset += 4;
    
    // Version
    let version = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
    offset += 2;
    
    // Skip random (32 bytes)
    offset += 32;
    
    // Session ID
    if offset >= data.len() { return None; }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;
    
    // Cipher suites
    if offset + 2 > data.len() { return None; }
    let cipher_suites_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
    offset += 2;
    
    let mut cipher_suites = Vec::new();
    for _ in 0..(cipher_suites_len / 2) {
        if offset + 2 > data.len() { break; }
        let cipher = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        cipher_suites.push(cipher);
        offset += 2;
    }
    
    // Compression methods
    if offset >= data.len() { return None; }
    let compression_len = data[offset] as usize;
    offset += 1 + compression_len;
    
    // Extensions
    if offset + 2 > data.len() { return None; }
    let extensions_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
    offset += 2;
    
    let mut extensions = Vec::new();
    let mut server_name = String::new();
    let mut alpn_protocols = Vec::new();
    let ext_end = offset + extensions_len;
    
    while offset + 4 <= ext_end && offset + 4 <= data.len() {
        let ext_type = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        let ext_len = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
        offset += 4;
        
        if offset + ext_len > data.len() { break; }
        
        extensions.push(ext_type);
        
        // Parse specific extensions
        match ext_type {
            0x0000 => { // server_name (SNI)
                if ext_len >= 3 {
                    let list_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
                    if list_len >= 3 && ext_len >= list_len {
                        let name_type = data[offset + 2];
                        if name_type == 0x00 { // host_name
                            let name_len = ((data[offset + 3] as usize) << 8) | (data[offset + 4] as usize);
                            if list_len >= 3 + name_len {
                                let name_start = offset + 5;
                                let name_end = name_start + name_len;
                                if name_end <= data.len() {
                                    server_name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
                                }
                            }
                        }
                    }
                }
            }
            0x0010 => { // ALPN
                if ext_len >= 3 {
                    let mut proto_offset = offset + 2;
                    while proto_offset + 1 <= offset + ext_len && proto_offset + 1 < data.len() {
                        let proto_len = data[proto_offset] as usize;
                        proto_offset += 1;
                        if proto_offset + proto_len <= offset + ext_len && proto_offset + proto_len <= data.len() {
                            let proto = String::from_utf8_lossy(&data[proto_offset..proto_offset + proto_len]).to_string();
                            alpn_protocols.push(proto);
                        }
                        proto_offset += proto_len;
                    }
                }
            }
            _ => {}
        }
        
        offset += ext_len;
    }
    
    Some(TLSClientHello {
        raw_version: version,
        raw_cipher_suites: cipher_suites,
        raw_extensions: extensions,
        server_name,
        alpn_protocols,
        supported_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        ec_point_formats: Vec::new(),
        greases: Vec::new(),
        supported_versions: Vec::new(),
        key_share: None,
        psk_key_exchange_modes: Vec::new(),
        record_size_limit: None,
        transport_parameters: None,
    })
}

fn compute_ja3(ch: &TLSClientHello) -> (String, String) {
    let version = if ch.raw_version >= 0x0304 { "771" } else { "769" };
    
    let mut ciphers = Vec::new();
    let mut greases_in_ciphers = Vec::new();
    for c in &ch.raw_cipher_suites {
        if is_grease(*c) {
            greases_in_ciphers.push(*c);
        } else {
            ciphers.push(format!("{:04x}", c));
        }
    }
    let cipher_str = ciphers.join("-");
    
    let mut exts = Vec::new();
    let mut greases_in_exts = Vec::new();
    for e in &ch.raw_extensions {
        if is_grease(*e) {
            greases_in_exts.push(*e);
        } else {
            exts.push(format!("{:04x}", e));
        }
    }
    let ext_str = exts.join("-");
    
    let ja3 = format!("{},{},{}", version, cipher_str, ext_str);
    let ja3_hash = format!("{:x}", md5::compute(ja3.as_bytes()));
    
    (ja3, ja3_hash)
}

fn compute_ja4(ch: &TLSClientHello) -> String {
    let version = if ch.raw_version >= 0x0304 { "13" } else { "12" };
    
    // Get first 3 non-GREASE cipher suites
    let mut cipher_parts = Vec::new();
    for c in &ch.raw_cipher_suites {
        if !is_grease(*c) {
            cipher_parts.push(format!("{:04x}", c));
            if cipher_parts.len() >= 3 {
                break;
            }
        }
    }
    
    // Pad with underscores if fewer than 3
    while cipher_parts.len() < 3 {
        cipher_parts.push("__".to_string());
    }
    // Determine if HTTP/2 is negotiated via ALPN or ciphers
    let http2 = ch.alpn_protocols.iter().any(|p| p == "h2") ||
                ch.raw_cipher_suites.iter().any(|c| *c >= 0xcc00 && *c <= 0xcc0f);
    
    let alpn = if http2 { "h2" } else { "_" };
    
    format!("t{}{}{}", version, alpn, cipher_parts.join(""))
}

fn detect_browser_from_fingerprint(ch: &TLSClientHello) -> String {
    // Check for TLS 1.3 indicators
    if ch.raw_version >= 0x0304 {
        // Check for TLS 1.3-specific extensions
        if ch.raw_extensions.contains(&0x002d) &&  // key_share
           ch.raw_extensions.contains(&0x002b) &&  // supported_versions
           ch.raw_extensions.contains(&0x0026) {   // psk_key_exchange_modes
            return "chrome".to_string();
        }
    }
    
    // Check cipher suite patterns
    if ch.raw_cipher_suites.contains(&0x1301) || 
       ch.raw_cipher_suites.contains(&0x1302) ||
       ch.raw_cipher_suites.contains(&0x1303) {
        return "chrome".to_string();
    }
    
    // Check for GREASE
    if ch.greases.is_empty() {
        return "unknown".to_string();
    }
    
    "chrome".to_string()
}

#[repr(C)]
pub struct TLSFingerprint {
    pub timestamp_ms: u64,
    pub server_ip: *mut c_char,
    pub server_port: u16,
    pub tls_version: *mut c_char,
    pub ja3_string: *mut c_char,
    pub ja3_hash: *mut c_char,
    pub ja4: *mut c_char,
    pub cipher_suites: *mut c_char,
    pub cipher_count: usize,
    pub greases_in_ciphers: *mut c_char,
    pub extensions: *mut c_char,
    pub extension_count: usize,
    pub greases_in_extensions: *mut c_char,
    pub alpn: *mut c_char,
    pub has_http2: bool,
    pub has_grease: bool,
    pub grease_values: *mut c_char,
    pub sni: *mut c_char,
    pub detected_browser: *mut c_char,
    pub anomalies: *mut c_char,
    pub trace_id: *mut c_char,
    pub raw_json: *mut c_char,
}

impl Default for TLSFingerprint {
    fn default() -> Self {
        TLSFingerprint {
            timestamp_ms: 0,
            server_ip: std::ptr::null_mut(),
            server_port: 0,
            tls_version: std::ptr::null_mut(),
            ja3_string: std::ptr::null_mut(),
            ja3_hash: std::ptr::null_mut(),
            ja4: std::ptr::null_mut(),
            cipher_suites: std::ptr::null_mut(),
            cipher_count: 0,
            greases_in_ciphers: std::ptr::null_mut(),
            extensions: std::ptr::null_mut(),
            extension_count: 0,
            greases_in_extensions: std::ptr::null_mut(),
            alpn: std::ptr::null_mut(),
            has_http2: false,
            has_grease: false,
            grease_values: std::ptr::null_mut(),
            sni: std::ptr::null_mut(),
            detected_browser: std::ptr::null_mut(),
            anomalies: std::ptr::null_mut(),
            trace_id: std::ptr::null_mut(),
            raw_json: std::ptr::null_mut(),
        }
    }
}

fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_else(|_| CString::new("").unwrap()).into_raw()
}

#[no_mangle]
pub extern "C" fn tls_fingerprint(
    host: *const c_char,
    port: libc::c_int,
) -> *mut TLSFingerprint {
    if host.is_null() {
        return std::ptr::null_mut();
    }

    let host_str = unsafe {
        match CStr::from_ptr(host).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let addr = format!("{}:{}", host_str, port);
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    
    let trace_id = format!("{:x}-{:x}", timestamp, rand_simple(&host_str));
    
    // Connect
    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{}] Connection failed: {}", trace_id, e);
            return std::ptr::null_mut();
        }
    };
    
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();

    // Send TLS ClientHello
    let client_hello = build_client_hello(&host_str);
    
    if let Err(e) = stream.write_all(&client_hello) {
        eprintln!("[{}] Write failed: {}", trace_id, e);
        return std::ptr::null_mut();
    }
    
    // Read response
    let mut response = vec![0u8; 8192];
    let n = match stream.read(&mut response) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[{}] Read failed: {}", trace_id, e);
            return std::ptr::null_mut();
        }
    };
    
    if n == 0 {
        eprintln!("[{}] No response", trace_id);
        return std::ptr::null_mut();
    }
    
    response.truncate(n);
    
    // Parse ClientHello from what we sent
    let ch = match parse_client_hello(&client_hello) {
        Some(c) => c,
        None => {
            eprintln!("[{}] Failed to parse ClientHello", trace_id);
            return std::ptr::null_mut();
        }
    };
    
    // Compute fingerprints
    let (ja3_string, ja3_hash) = compute_ja3(&ch);
    let ja4 = compute_ja4(&ch);
    let browser = detect_browser_from_fingerprint(&ch);
    
    // Collect greases
    let greases: Vec<u16> = ch.raw_cipher_suites.iter()
        .chain(ch.raw_extensions.iter())
        .filter(|&&v| is_grease(v))
        .copied()
        .collect();
    
    let greases_str: String = greases.iter()
        .map(|g| get_grease_name(*g))
        .collect::<Vec<_>>()
        .join(",");
    
    let cipher_str: String = ch.raw_cipher_suites.iter()
        .map(|c| get_cipher_name(*c))
        .collect::<Vec<_>>()
        .join(",");
    
    let greases_in_ciphers: String = ch.raw_cipher_suites.iter()
        .filter(|&&c| is_grease(c))
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");
    
    let ext_str: String = ch.raw_extensions.iter()
        .map(|e| get_extension_name(*e))
        .collect::<Vec<_>>()
        .join(",");
    
    let greases_in_exts: String = ch.raw_extensions.iter()
        .filter(|&&e| is_grease(e))
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");
    
    // Build result
    let mut fp = Box::new(TLSFingerprint::default());
    fp.timestamp_ms = timestamp;
    fp.server_ip = to_c_string(&host_str);
    fp.server_port = port as u16;
    fp.tls_version = to_c_string(&format!("0x{:04x}", ch.raw_version));
    fp.ja3_string = to_c_string(&ja3_string);
    fp.ja3_hash = to_c_string(&ja3_hash);
    fp.ja4 = to_c_string(&ja4);
    fp.cipher_suites = to_c_string(&cipher_str);
    fp.cipher_count = ch.raw_cipher_suites.len();
    fp.greases_in_ciphers = to_c_string(&greases_in_ciphers);
    fp.extensions = to_c_string(&ext_str);
    fp.extension_count = ch.raw_extensions.len();
    fp.greases_in_extensions = to_c_string(&greases_in_exts);
    fp.alpn = to_c_string(&ch.alpn_protocols.join(","));
    fp.has_http2 = ch.alpn_protocols.contains(&"h2".to_string());
    fp.has_grease = !greases.is_empty();
    fp.grease_values = to_c_string(&greases_str);
    fp.sni = to_c_string(&ch.server_name);
    fp.detected_browser = to_c_string(&browser);
    fp.anomalies = to_c_string("");
    fp.trace_id = to_c_string(&trace_id);
    
    // JSON for debugging
    let json = serde_json::json!({
        "timestamp_ms": timestamp,
        "trace_id": trace_id,
        "server": format!("{}:{}", host_str, port),
        "tls_version": format!("0x{:04x}", ch.raw_version),
        "ja3": ja3_string,
        "ja3_hash": ja3_hash,
        "ja4": ja4,
        "browser": browser,
        "ciphers": ch.raw_cipher_suites.iter().map(|c| format!("0x{:04x}", c)).collect::<Vec<_>>(),
        "cipher_count": ch.raw_cipher_suites.len(),
        "extensions": ch.raw_extensions.iter().map(|e| format!("0x{:04x}", e)).collect::<Vec<_>>(),
        "extension_count": ch.raw_extensions.len(),
        "greases": greases,
        "alpn": ch.alpn_protocols,
    }).to_string();
    fp.raw_json = to_c_string(&json);
    
    eprintln!("[{}] Fingerprint: JA4={}, JA3={}, Browser={}", 
        trace_id, ja4, ja3_hash, browser);
    
    Box::into_raw(fp)
}

#[no_mangle]
pub extern "C" fn connect_and_fingerprint(host: *const c_char, port: libc::c_int) -> *mut TLSFingerprint {
    tls_fingerprint(host, port)
}

fn rand_simple(seed: &str) -> u64 {
    let mut h: u64 = 0x123456789abcdef0;
    for b in seed.as_bytes() {
        h = h.wrapping_mul(31).wrapping_add(*b as u64);
    }
    h
}

fn build_client_hello(hostname: &str) -> Vec<u8> {
    // Build a minimal TLS 1.3 ClientHello
    let mut hello = Vec::new();
    
    // TLS Record: Handshake (22) + Version (0x0303) + Length (will fill)
    hello.push(0x16); // Handshake
    hello.push(0x03); // Version major
    hello.push(0x03); // Version minor
    hello.push(0x00); // Length placeholder high
    hello.push(0x00); // Length placeholder low
    
    // Handshake type: ClientHello (1)
    hello.push(0x01);
    
    // Handshake length (will fill in)
    let handshake_start = hello.len();
    hello.push(0x00);
    hello.push(0x00);
    hello.push(0x00);
    
    // Client version (TLS 1.3)
    hello.push(0x03);
    hello.push(0x03);
    
    // Random (32 bytes)
    let random: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    hello.extend_from_slice(&random);
    
    // Session ID length (0)
    hello.push(0x00);
    
    // Cipher suites - TLS 1.3 + common
    let ciphers = vec![
        0x1301, 0x1302, 0x1303, 0xcca8, 0xcca9, // TLS 1.3
        0xc02b, 0xc02c, 0xc02f, 0xc030, // ECDHE
        0x009c, 0x009d, 0x002f, 0x0035, // RSA/AES
    ];
    let cipher_len = ciphers.len() * 2;
    hello.push((cipher_len >> 8) as u8);
    hello.push(cipher_len as u8);
    for c in &ciphers {
        hello.push((c >> 8) as u8);
        hello.push(*c as u8);
    }
    
    // Compression (null only)
    hello.push(0x01);
    hello.push(0x00);
    
    // Build extensions first so we can calculate length
    let mut extensions = Vec::new();
    
    // SNI
    let sni_bytes = hostname.as_bytes();
    
    // SNI extension format:
    // - extension type: 2 bytes (0x0000 for server_name)
    // - extension length: 2 bytes  
    // - server_name_list:
    //   - list length: 2 bytes
    //   - name_type: 1 byte (0x00 = host_name)
    //   - name_length: 2 bytes
    //   - hostname: n bytes
    let sni_name_len = 1 + 2 + sni_bytes.len(); // name_type(1) + name_len(2) + hostname
    let sni_list_len = sni_name_len; // list contains one name
    let sni_ext_len = sni_list_len; // extension data length
    
    // Extension header
    extensions.push(0x00); // server_name extension type (upper byte)
    extensions.push(0x00); // server_name extension type (lower byte)
    // Extension length (big endian)
    extensions.push((sni_ext_len >> 8) as u8);
    extensions.push(sni_ext_len as u8);
    // SNI data starts here - server_name_list
    // server_name_list length (big endian)
    extensions.push((sni_list_len >> 8) as u8);
    extensions.push(sni_list_len as u8);
    // First server name
    extensions.push(0x00); // name_type = host_name (1 byte)
    // hostname length (big endian, 2 bytes)
    extensions.push((sni_bytes.len() >> 8) as u8);
    extensions.push(sni_bytes.len() as u8);
    // hostname
    extensions.extend_from_slice(sni_bytes);
    
    // Supported versions (TLS 1.3)
    extensions.push(0x00); // supported_versions
    extensions.push(0x00);
    extensions.push(0x00); // length
    extensions.push(0x02); // length = 2
    extensions.push(0x03); // TLS 1.3
    extensions.push(0x03);
    
    // Supported groups
    extensions.push(0x00); // supported_groups
    extensions.push(0x00);
    extensions.push(0x00); // length
    extensions.push(0x04); // length = 4
    extensions.push(0x1d); // x25519
    extensions.push(0x17); // secp256r1
    extensions.push(0x1e); // x448
    extensions.push(0x29); // secp384r1
    
    // Signature algorithms
    extensions.push(0x00); // signature_algorithms
    extensions.push(0x00);
    extensions.push(0x00); // length
    extensions.push(0x08); // length = 8
    extensions.push(0x04); // rsa_pkcs1_sha256
    extensions.push(0x05); // rsa_pkcs1_sha384
    extensions.push(0x06); // rsa_pkcs1_sha512
    extensions.push(0x08); // rsa_pss_pss_sha256
    extensions.push(0x09); // rsa_pss_pss_sha384
    extensions.push(0x0a); // rsa_pss_pss_sha512
    extensions.push(0x0b); // ecdsa_secp256r1_sha256
    extensions.push(0x0c); // ecdsa_secp384r1_sha384
    
    // ALPN - h2 and http/1.1
    let h2: &[u8] = b"h2";
    let http11: &[u8] = b"http/1.1";
    let alpn_protocols: Vec<&[u8]> = vec![h2, http11];
    let mut alpn_data = Vec::new();
    for proto in &alpn_protocols {
        alpn_data.push(proto.len() as u8);
        alpn_data.extend_from_slice(proto);
    }
    let alpn_ext_len = 2 + alpn_data.len(); // protocols_length(2) + all protocols
    extensions.push(0x00); // application_layer_protocol_negotiation
    extensions.push(0x10);
    extensions.push((alpn_ext_len >> 8) as u8);
    extensions.push(alpn_ext_len as u8);
    extensions.push((alpn_data.len() >> 8) as u8);
    extensions.push(alpn_data.len() as u8);
    extensions.extend_from_slice(&alpn_data);
    
    // Key share
    extensions.push(0x00); // key_share
    extensions.push(0x00);
    extensions.push(0x00); // length
    extensions.push(0x26); // length = 38
    extensions.push(0x1d); // x25519
    extensions.push(0x00); // key length = 0 for client
    
    // PSK key exchange modes
    extensions.push(0x00); // psk_key_exchange_modes
    extensions.push(0x26);
    extensions.push(0x00); // length
    extensions.push(0x02); // length = 2
    extensions.push(0x01); // psk_dhe_ke
    
    // Now add extensions length and extensions to hello
    let ext_len = extensions.len();
    hello.push((ext_len >> 8) as u8);
    hello.push(ext_len as u8);
    hello.extend_from_slice(&extensions);
    
    // Update handshake length
    let handshake_len = hello.len() - handshake_start - 3;
    hello[handshake_start] = ((handshake_len >> 16) & 0xff) as u8;
    hello[handshake_start + 1] = ((handshake_len >> 8) & 0xff) as u8;
    hello[handshake_start + 2] = (handshake_len & 0xff) as u8;
    
    // Update record length
    let record_len = hello.len() - 5;
    hello[3] = ((record_len >> 8) & 0xff) as u8;
    hello[4] = (record_len & 0xff) as u8;
    
    hello
}

#[no_mangle]
pub extern "C" fn free_tls_fingerprint(fp: *mut TLSFingerprint) {
    if fp.is_null() {
        return;
    }
    
    unsafe {
        let f = Box::from_raw(fp);
        
        if !f.server_ip.is_null() { let _ = CString::from_raw(f.server_ip); }
        if !f.tls_version.is_null() { let _ = CString::from_raw(f.tls_version); }
        if !f.ja3_string.is_null() { let _ = CString::from_raw(f.ja3_string); }
        if !f.ja3_hash.is_null() { let _ = CString::from_raw(f.ja3_hash); }
        if !f.ja4.is_null() { let _ = CString::from_raw(f.ja4); }
        if !f.cipher_suites.is_null() { let _ = CString::from_raw(f.cipher_suites); }
        if !f.greases_in_ciphers.is_null() { let _ = CString::from_raw(f.greases_in_ciphers); }
        if !f.extensions.is_null() { let _ = CString::from_raw(f.extensions); }
        if !f.greases_in_extensions.is_null() { let _ = CString::from_raw(f.greases_in_extensions); }
        if !f.alpn.is_null() { let _ = CString::from_raw(f.alpn); }
        if !f.grease_values.is_null() { let _ = CString::from_raw(f.grease_values); }
        if !f.sni.is_null() { let _ = CString::from_raw(f.sni); }
        if !f.detected_browser.is_null() { let _ = CString::from_raw(f.detected_browser); }
        if !f.anomalies.is_null() { let _ = CString::from_raw(f.anomalies); }
        if !f.trace_id.is_null() { let _ = CString::from_raw(f.trace_id); }
        if !f.raw_json.is_null() { let _ = CString::from_raw(f.raw_json); }
    }
}
