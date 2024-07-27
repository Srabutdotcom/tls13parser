// src/tools.js
function getUint8BE(data, pos = 0, length = 1) {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError("Input data must be a byte array");
  }
  if (pos < 0 || pos >= data.length) {
    throw new TypeError("Position is out of bounds");
  }
  if (length < 1) {
    throw new TypeError("Length must be at least 1");
  }
  if (pos + length > data.length) {
    throw TypeError(`length is beyond data.length`);
  }
  let output = 0;
  for (let i = pos; i < pos + length; i++) {
    output = output << 8 | data[i];
  }
  return output;
}
function getUint8(data, pos) {
  return getUint8BE(data, pos, 1);
}
function getUint16(data, pos) {
  return getUint8BE(data, pos, 2);
}
function getUint24(data, pos) {
  return getUint8BE(data, pos, 3);
}
function getUint32(data, pos) {
  return getUint8BE(data, pos, 4);
}
var Uint8View = class extends Uint8Array {
  #pos = 0;
  constructor(uint8Array, pos = 0) {
    super(uint8Array);
    this.#pos = pos;
  }
  uint8() {
    const out = getUint8(this, this.#pos);
    this.#pos++;
    return out;
  }
  uint16() {
    const out = getUint16(this, this.#pos);
    this.#pos += 2;
    return out;
  }
  uint24() {
    const out = getUint24(this, this.#pos);
    this.#pos += 3;
    return out;
  }
  uint32() {
    const out = getUint32(this, this.#pos);
    this.#pos += 4;
    return out;
  }
  /**
   * return a section of Uint8Array with specified length, the position is already defined in Uint8View
   * @param {uint} length 
   * @returns {Uint8Array}
   */
  slice(length) {
    const copy = new Uint8Array(this.buffer);
    const out = length !== void 0 ? copy.slice(this.#pos, this.#pos + length) : copy.slice(this.#pos);
    return out;
  }
  sliceMovePos(length) {
    const o = this.slice(length);
    this.#pos += length;
    return o;
  }
  get pos() {
    return this.#pos;
  }
  posAdd(uint) {
    this.#pos += uint;
  }
};
function ensureUint8View(value, pos) {
  if (value instanceof Uint8View == false)
    return new Uint8View(value, pos);
  return value;
}
function uinToHex(uint, length) {
  return Number(uint).toString(16).padStart(length + 2, `0x` + "0".repeat(length));
}

// src/extsfull.js
var dec = new TextDecoder();
var extsfull = {
  0: { name: "server_name", tls13: "CH, EE, CR", ref: "[RFC6066][RFC9261]" },
  1: {
    name: "max_fragment_length",
    tls13: "CH, EE",
    ref: "[RFC6066][RFC8449]"
  },
  2: { name: "client_certificate_url", tls13: "-", ref: "[RFC6066]" },
  3: { name: "trusted_ca_keys", tls13: "-", ref: "[RFC6066]" },
  4: {
    name: "truncated_hmac",
    tls13: "-",
    ref: "[RFC6066][IESG Action 2018-08-16]"
  },
  5: { name: "status_request", tls13: "CH, CR, CT", ref: "[RFC6066]" },
  6: { name: "user_mapping", tls13: "-", ref: "[RFC4681]" },
  7: { name: "client_authz", tls13: "-", ref: "[RFC5878]" },
  8: { name: "server_authz", tls13: "-", ref: "[RFC5878]" },
  9: { name: "cert_type", tls13: "-", ref: "[RFC6091]" },
  10: { name: "supported_groups", tls13: "CH, EE", ref: "[RFC8422][RFC7919]" },
  11: { name: "ec_point_formats", tls13: "-", ref: "[RFC8422]" },
  12: { name: "srp", tls13: "-", ref: "[RFC5054]" },
  13: { name: "signature_algorithms", tls13: "CH, CR", ref: "[RFC8446]" },
  14: { name: "use_srtp", tls13: "CH, EE", ref: "[RFC5764]" },
  15: { name: "heartbeat", tls13: "CH, EE", ref: "[RFC6520]" },
  16: {
    name: "application_layer_protocol_negotiation",
    tls13: "CH, EE",
    ref: "[RFC7301]"
  },
  17: { name: "status_request_v2", tls13: "-", ref: "[RFC6961]" },
  18: {
    name: "signed_certificate_timestamp",
    tls13: "CH, CR, CT",
    ref: "[RFC6962]"
  },
  19: { name: "client_certificate_type", tls13: "CH, EE", ref: "[RFC7250]" },
  20: { name: "server_certificate_type", tls13: "CH, EE", ref: "[RFC7250]" },
  21: { name: "padding", tls13: "CH", ref: "[RFC7685]" },
  22: { name: "encrypt_then_mac", tls13: "-", ref: "[RFC7366]" },
  23: { name: "extended_master_secret", tls13: "-", ref: "[RFC7627]" },
  24: { name: "token_binding", tls13: "-", ref: "[RFC8472]" },
  25: { name: "cached_info", tls13: "-", ref: "[RFC7924]" },
  26: { name: "tls_lts", tls13: "-", ref: "[draft-gutmann-tls-lts]" },
  27: { name: "compress_certificate", tls13: "CH, CR", ref: "[RFC8879]" },
  28: { name: "record_size_limit", tls13: "CH, EE", ref: "[RFC8449]" },
  29: { name: "pwd_protect", tls13: "CH", ref: "[RFC8492]" },
  30: { name: "pwd_clear", tls13: "CH", ref: "[RFC8492]" },
  31: { name: "password_salt", tls13: "CH, SH, HRR", ref: "[RFC8492]" },
  32: { name: "ticket_pinning", tls13: "CH, EE", ref: "[RFC8672]" },
  33: { name: "tls_cert_with_extern_psk", tls13: "CH, SH", ref: "[RFC8773]" },
  34: { name: "delegated_credential", tls13: "CH, CR, CT", ref: "[RFC9345]" },
  35: { name: "session_ticket", tls13: "-", ref: "[RFC5077][RFC8447]" },
  36: { name: "TLMSP", tls13: "-", ref: "[ETSI TS 103 523-2]" },
  37: { name: "TLMSP_proxying", tls13: "-", ref: "[ETSI TS 103 523-2]" },
  38: { name: "TLMSP_delegate", tls13: "-", ref: "[ETSI TS 103 523-2]" },
  39: { name: "supported_ekt_ciphers", tls13: "CH, EE", ref: "[RFC8870]" },
  41: { name: "pre_shared_key", tls13: "CH, SH", ref: "[RFC8446]" },
  42: { name: "early_data", tls13: "CH, EE, NST", ref: "[RFC8446]" },
  43: { name: "supported_versions", tls13: "CH, SH, HRR", ref: "[RFC8446]" },
  44: { name: "cookie", tls13: "CH, HRR", ref: "[RFC8446]" },
  45: { name: "psk_key_exchange_modes", tls13: "CH", ref: "[RFC8446]" },
  47: { name: "certificate_authorities", tls13: "CH, CR", ref: "[RFC8446]" },
  48: { name: "oid_filters", tls13: "CR", ref: "[RFC8446]" },
  49: { name: "post_handshake_auth", tls13: "CH", ref: "[RFC8446]" },
  50: { name: "signature_algorithms_cert", tls13: "CH, CR", ref: "[RFC8446]" },
  51: { name: "key_share", tls13: "CH, SH, HRR", ref: "[RFC8446]" },
  52: { name: "transparency_info", tls13: "CH, CR, CT", ref: "[RFC9162]" },
  53: { name: "connection_id_deprecated", tls13: "-", ref: "[RFC9146]" },
  54: { name: "connection_id", tls13: "CH, SH", ref: "[RFC9146]" },
  55: { name: "external_id_hash", tls13: "CH, EE", ref: "[RFC8844]" },
  56: { name: "external_session_id", tls13: "CH, EE", ref: "[RFC8844]" },
  57: { name: "quic_transport_parameters", tls13: "CH, EE", ref: "[RFC9001]" },
  58: { name: "ticket_request", tls13: "CH, EE", ref: "[RFC9149]" },
  59: {
    name: "dnssec_chain",
    tls13: "CH, CT",
    ref: "[RFC9102][RFC Errata 6860]"
  },
  60: {
    name: "sequence_number_encryption_algorithms",
    tls13: "CH, HRR, SH",
    ref: "[draft-pismenny-tls-dtls-plaintext-sequence-number-01]"
  },
  61: { name: "rrc", tls13: "CH, SH", ref: "[draft-ietf-tls-dtls-rrc-10]" },
  64768: {
    name: "ech_outer_extensions",
    tls13: "CH [2]",
    ref: "[draft-ietf-tls-esni-17]"
  },
  65037: {
    name: "encrypted_client_hello",
    tls13: "CH, HRR, EE",
    ref: "[draft-ietf-tls-esni-17]"
  },
  65281: { name: "renegotiation_info", tls13: "-", ref: "[RFC5746]" }
};
var functions = {
  0: server_name,
  1: max_fragment_length,
  10: supported_groups,
  13: signature_algorithms,
  28: record_size_limit,
  43: supported_versions,
  44: cookie,
  51: key_share
};
function extsBase(code, length, value) {
  const id = extsfull[code] ?? code;
  const data = functions[code] ? functions[code](value, length) : baseExt(value, length);
  return {
    id,
    data,
    length
  };
}
function baseExt(value, length) {
  const sliced = value.sliceMovePos(length);
  return sliced;
}
function server_name(value) {
  const server_name_list = [];
  const payloadLength = value.uint16();
  const end = value.pos + payloadLength;
  while (true) {
    const typeCode = value.uint8();
    const hostType = typeCode == 0 ? "0-hostname" : `${typeCode}-unknown`;
    const payloadLength2 = value.uint16();
    const hostNameBytes = value.sliceMovePos(payloadLength2);
    server_name_list.push({
      type: hostType,
      name: dec.decode(hostNameBytes)
    });
    if (value.pos >= end)
      break;
  }
  return server_name_list;
}
function max_fragment_length(value) {
  const types2 = Object.freeze({
    1: 2 ** 9,
    2: 2 ** 10,
    3: 2 ** 11,
    4: 2 ** 12
  });
  const typeCode = value.uint8();
  if (typeCode < 1 || typeCode > 4) {
    throw TypeError(`Expected code between 1 to 4 but got ${typeCode}`);
  }
  return types2[typeCode];
}
function record_size_limit(value) {
  return value.uint16();
}
function supported_groups(value) {
  const supportedGroups = [];
  const payloadLength = value.uint16();
  const end = value.pos + payloadLength;
  while (true) {
    const code = value.uint16();
    const group = namedGroup[code] ?? "unknown";
    supportedGroups.push(`${uinToHex(code, 4)}-${group}`);
    if (value.pos >= end)
      break;
  }
  return supportedGroups;
}
function signature_algorithms(value) {
  const signatureAlgoritm = [];
  const payloadLength = value.uint16();
  const end = value.pos + payloadLength;
  while (true) {
    const code = value.uint16();
    const algo = SignatureScheme[code] ?? "unknown";
    signatureAlgoritm.push(`${uinToHex(code, 4)}-${algo}`);
    if (value.pos >= end)
      break;
  }
  return signatureAlgoritm;
}
function supported_versions(value, length) {
  const isOdd = (length & 1) !== 0;
  if (isOdd) {
    const versions = [];
    const len = value.uint8();
    const end = value.pos + len;
    while (true) {
      const code2 = value.uint16();
      if (code2 < 771)
        throw TypeError(`at least TLS 1.2-0x0303`);
      versions.push(`${uinToHex(code2, 4)}-${tlsversions[code2]}`);
      if (value.pos >= end)
        break;
    }
    return versions;
  }
  const code = value.uint16();
  return `${uinToHex(code, 4)}-${tlsversions[code]}`;
}
function cookie(value) {
  const len = value.uint16();
  const _cookie = value.sliceMovePos(len);
  return _cookie;
}
function key_share(value) {
  if (value.type == "client_hello")
    return keyShareClientHello(value);
  return keyShareEntry(value);
}
function keyShareClientHello(value) {
  const payloadLength = value.uint16();
  const end = value.pos + payloadLength;
  const _keyShare = [];
  while (true) {
    _keyShare.push(keyShareEntry(value));
    if (value.pos >= end)
      break;
  }
  return _keyShare;
}
function keyShareEntry(value) {
  const group = value.uint16();
  const keyLength = value.uint16();
  const keyShare = value.sliceMovePos(keyLength);
  return {
    name: `${group}-${namedGroup[group] ?? "unknown"}`,
    key: keyShare
  };
}
var tlsversions = Object.freeze({
  768: "SSL 3.0",
  769: "TLS 1.0",
  770: "TLS 1.1",
  771: "TLS 1.2",
  772: "TLS 1.3"
});
var namedGroup = Object.freeze({
  /* Elliptic Curve Groups (ECDHE) */
  23: "secp256r1",
  24: "secp384r1",
  25: "secp521r1",
  29: "x25519",
  30: "x448",
  /* Finite Field Groups (DHE) */
  256: "ffdhe2048",
  257: "ffdhe3072",
  258: "ffdhe4096",
  259: "ffdhe6144",
  260: "ffdhe8192"
  /*0xFFFF-16 bytes-max*/
});
var SignatureScheme = Object.freeze({
  /* RSASSA-PKCS1-v1_5 algorithms */
  1025: "rsa_pkcs1_sha256",
  1281: "rsa_pkcs1_sha384",
  1537: "rsa_pkcs1_sha512",
  /* ECDSA algorithms */
  1027: "ecdsa_secp256r1_sha256",
  1283: "ecdsa_secp384r1_sha384",
  1539: "ecdsa_secp521r1_sha512",
  /* RSASSA-PSS algorithms with public key OID rsaEncryption */
  2052: "rsa_pss_rsae_sha256",
  2053: "rsa_pss_rsae_sha384",
  2054: "rsa_pss_rsae_sha512",
  /* EdDSA algorithms */
  2055: "ed25519",
  2056: "ed448",
  /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
  2057: "rsa_pss_pss_sha256",
  2058: "rsa_pss_pss_sha384",
  2059: "rsa_pss_pss_sha512",
  /* Legacy algorithms */
  513: "rsa_pkcs1_sha1",
  515: "ecdsa_sha1"
  /*0xFFFF - 16 bytes - max*/
});

// src/extension.js
var dec2 = new TextDecoder();
var namedGroup2 = Object.freeze({
  /* Elliptic Curve Groups (ECDHE) */
  23: "secp256r1",
  24: "secp384r1",
  25: "secp521r1",
  29: "x25519",
  30: "x448",
  /* Finite Field Groups (DHE) */
  256: "ffdhe2048",
  257: "ffdhe3072",
  258: "ffdhe4096",
  259: "ffdhe6144",
  260: "ffdhe8192"
  /*0xFFFF-16 bytes-max*/
});

// src/handshake.js
var handShakes = Object.freeze({
  0: "HelloRequest",
  //RESERVED
  1: ClientHello,
  2: ServerHello,
  4: NewSessionTicket,
  8: EncryptedExtensions,
  //(TLS 1.3 only)
  11: Certificate,
  12: "ServerKeyExchange",
  //RESERVED
  13: CertificateRequest,
  14: "ServerHelloDone",
  //RESERVED
  15: CertificateVerify,
  16: "ClientKeyExchange",
  //RESERVED
  20: Finished
});
function Handshake(_value, pos) {
  const value = ensureUint8View(_value, pos);
  const typeCode = value.uint8();
  const typeFunc = typeof handShakes[typeCode] == "string" ? genericHandshake : handShakes[typeCode];
  const name = typeof handShakes[typeCode] == "string" ? handShakes[typeCode] : typeFunc.name;
  const payloadLength = value.uint24();
  return {
    length: payloadLength,
    [name]: typeFunc(value, payloadLength, name),
    value
  };
}
var cipherEnums = Object.freeze({
  4865: "TLS_AES_128_GCM_SHA256",
  4866: "TLS_AES_256_GCM_SHA384",
  4867: "TLS_CHACHA20_POLY1305_SHA256",
  4868: "TLS_AES_128_CCM_SHA256",
  4869: "TLS_AES_128_CCM_8_SHA256"
});
function sessionId(value) {
  const length = value.uint8();
  if (length == 0)
    return;
  const _sessionId = value.sliceMovePos(length);
  return _sessionId;
}
function extension(value) {
  const length = value.uint16();
  if (length == 0)
    throw TypeError(`must have extension`);
  const exts = {
    length
  };
  const end = length + value.pos;
  while (true) {
    const typeCode = value.uint16();
    const typeFull = extsfull[typeCode] ?? { name: typeCode };
    const length2 = value.uint16();
    exts[typeFull.name] = extsBase(typeCode, length2, value);
    if (value.pos >= end)
      break;
  }
  return exts;
}
function ServerHello(value, length, type = "server_hello") {
  value.type = "server_hello";
  const versionCode = value.uint16();
  if (versionCode !== 771) {
    throw TypeError(
      `Expected protocolVersion 0x0303 but got ${uinToHex(versionCode, 4)}`
    );
  }
  const version = `${uinToHex(versionCode, 4)}-TLS 1.2 (legacy protocol version)`;
  const random = value.sliceMovePos(32);
  const session_id = sessionId(value);
  const cipherCode = value.uint16();
  const cipher_suite = `${uinToHex(cipherCode, 4)}-${cipherEnums[cipherCode]}`;
  const compression_method = value.uint8();
  const extensions = extension(value);
  return {
    length,
    version,
    random,
    session_id,
    cipher_suite,
    compression_method,
    extensions
  };
}
function ClientHello(value, length) {
  value.type = "client_hello";
  const versionCode = value.uint16();
  if (versionCode !== 771) {
    throw TypeError(
      `Expected protocolVersion 0x0303 but got ${uinToHex(versionCode, 4)}`
    );
  }
  const version = `${uinToHex(versionCode, 4)}-TLS 1.2 (legacy protocol version)`;
  const random = value.sliceMovePos(32);
  const session_id = sessionId(value);
  const cipher_suites = cipherSuites(value);
  const compression_methods = compression(value);
  const extensions = extension(value);
  return {
    length,
    version,
    random,
    session_id,
    cipher_suites,
    compression_methods,
    extensions
  };
  function cipherSuites(value2) {
    const ciphers = [];
    const length2 = value2.uint16();
    if (length2 == 0)
      throw TypeError(`at least one cipherSuite list`);
    const end = value2.pos + length2;
    while (true) {
      const code = value2.uint16();
      ciphers.push(
        code
        //`${uinToHex(code, 4)}-${desc}`,
      );
      if (value2.pos >= end)
        break;
    }
    return ciphers;
  }
  function compression(value2) {
    const length2 = value2.uint8();
    if (length2 == 0)
      throw TypeError(`compression must have 1 length`);
    const code = value2.uint8();
    if (code !== 0) {
      throw TypeError(`expected compression code 0 but got ${code}`);
    }
    return `${uinToHex(code, 2)}-No Compression`;
  }
}
function NewSessionTicket(value, length) {
  const ticket_lifetime = value.uint32();
  const ticket_age_add = value.uint32();
  const ticket_nonceLen = value.uint8();
  const ticket_nonce = value.sliceMovePos(ticket_nonceLen);
  const ticketLen = value.uint16();
  const ticket = value.sliceMovePos(ticketLen);
  const extsLen = value.uint16();
  const extentions = value.sliceMovePos(extsLen);
  return {
    ticket_lifetime,
    ticket_age_add,
    ticket_nonce,
    ticket,
    extentions
  };
}
function EncryptedExtensions(value, length) {
  const len = value.uint16();
  return value.sliceMovePos(len);
}
function Certificate(value, length) {
  let len = value.uint8();
  const certificate_request_context = value.sliceMovePos(len);
  len = value.uint24();
  const certificate_list = [];
  while (true) {
    certificate_list.push(CertificateEntry(value, len));
    if (value.pos >= len)
      break;
  }
  return {
    certificate_request_context,
    certificate_list
    //FIXME - 
  };
}
function CertificateEntry(value, length) {
  let len = value.uint24();
  const certificate = value.sliceMovePos(len);
  len = value.uint16();
  const extensions = value.sliceMovePos(len);
  return {
    certificate,
    extensions
  };
}
function CertificateRequest(value, length) {
  let len = value.uint8();
  const certificate_request_context = value.sliceMovePos(len);
  len = value.uint16();
  const extensions = value.sliceMovePos(len);
  return {
    certificate_request_context,
    extensions
  };
}
function CertificateVerify(value, length) {
  const sigCode = value.uint16();
  const signatureAlgoritm = `${uinToHex(sigCode, 4)}-${SignatureScheme[sigCode]}`;
  const len = value.uint16();
  const signature = value.sliceMovePos(len);
  return {
    signatureAlgoritm,
    signature
  };
}
function Finished(value, length) {
  const verify_data = value.sliceMovePos(length);
  return {
    verify_data
  };
}
function genericHandshake(value, length, type) {
  value.type = type;
  return value.sliceMovePos(length);
}

// src/alert.js
function Alert(value, length) {
  const levelCode = value.uint8();
  const desCode = value.uint8();
  return {
    level: `${levelCode}-${levels[levelCode]}`,
    description: `${desCode}-${descriptions[desCode]}`
  };
}
var descriptions = {
  0: "close_notify",
  10: "unexpected_message",
  20: "bad_record_mac",
  21: "decryption_failed_RESERVED",
  22: "record_overflow",
  30: "decompression_failure_RESERVED",
  40: "handshake_failure",
  41: "no_certificate_RESERVED",
  42: "bad_certificate",
  43: "unsupported_certificate",
  44: "certificate_revoked",
  45: "certificate_expired",
  46: "certificate_unknown",
  47: "illegal_parameter",
  48: "unknown_ca",
  49: "access_denied",
  50: "decode_error",
  51: "decrypt_error",
  60: "export_restriction_RESERVED",
  70: "protocol_version",
  71: "insufficient_security",
  80: "internal_error",
  86: "inappropriate_fallback",
  90: "user_canceled",
  100: "no_renegotiation_RESERVED",
  109: "missing_extension",
  110: "unsupported_extension",
  111: "certificate_unobtainable_RESERVED",
  112: "unrecognized_name",
  113: "bad_certificate_status_response",
  114: "bad_certificate_hash_value_RESERVED",
  115: "unknown_psk_identity",
  116: "certificate_required",
  120: "no_application_protocol"
  /*255*/
};
var levels = Object.freeze({
  1: "warning",
  2: "fatal"
  /*255*/
});

// src/heartbeat.js
function Heartbeat(value, length) {
  const typeCode = value.uint8();
  if (!typeCode)
    throw TypeError(`unexpected heartbeat type ${typeCode}`);
  const type = types[typeCode];
  const payloadLength = value.uint16();
  const message = value.slice(payloadLength);
  const paddingLength = length - payloadLength - 3;
  if (paddingLength < 16)
    throw TypeError(`padding length must be at least 16 bytes`);
  return {
    type,
    message
  };
}
var types = Object.freeze({
  1: "request",
  2: "response"
  /*255:max value*/
});

// src/index.js
var Record = class {
  // TLSPlainText
  #value;
  constructor(value, pos) {
    this.#value = ensureUint8View(value, pos);
    this.pos = this.#value.pos;
    const typeCode = this.#value.uint8();
    this.type = records[typeCode]?.name;
    if (!this.type)
      throw TypeError(`Unexpected type of record value ${typeCode}`);
    this.version = this.#value.uint16();
    this.version = `${uinToHex(this.version, 4)}-TLS 1.x (legacy record version)`;
    this.length = this.#value.uint16();
    this[this.type] = records[typeCode](this.value, this.length);
  }
  get value() {
    return this.#value;
  }
  get header() {
    return Uint8Array.from(this.value).slice(this.pos, this.pos + 5);
  }
  get message() {
    return Uint8Array.from(this.value).slice(this.pos + 5, this.pos + 5 + this.length);
  }
};
function Invalid(value, length) {
  return `Invalid`;
}
function ChangeCipherSpec(value, length) {
  const code = value.uint8();
  if (code !== 1)
    throw TypeError(`unexpected value in ChangeCipherSpec`);
  return code;
}
function Application(value, length) {
  const data = value.sliceMovePos(length);
  return data;
}
var records = Object.freeze({
  //this.prototype.ContentTypes = {
  0: Invalid,
  20: ChangeCipherSpec,
  21: Alert,
  22: Handshake,
  23: Application,
  24: Heartbeat
  /* 255: 'Default' */
});
function Records(value) {
  value = ensureUint8View(value);
  let records2 = [];
  while (true) {
    const record = new Record(value, value.pos);
    records2.push(record);
    if (record.value.pos >= value.length)
      break;
  }
  return records2;
}
export {
  Handshake,
  Record,
  Records
};
