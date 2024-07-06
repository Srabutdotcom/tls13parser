import { uinToHex } from "./tools.js";

const dec = new TextDecoder();

/**
 * LINK - https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
 */

export const extsfull = {
   0: { name: "server_name", tls13: "CH, EE, CR", ref: "[RFC6066][RFC9261]" },
   1: {
      name: "max_fragment_length",
      tls13: "CH, EE",
      ref: "[RFC6066][RFC8449]",
   },
   2: { name: "client_certificate_url", tls13: "-", ref: "[RFC6066]" },
   3: { name: "trusted_ca_keys", tls13: "-", ref: "[RFC6066]" },
   4: {
      name: "truncated_hmac",
      tls13: "-",
      ref: "[RFC6066][IESG Action 2018-08-16]",
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
      ref: "[RFC7301]",
   },
   17: { name: "status_request_v2", tls13: "-", ref: "[RFC6961]" },
   18: {
      name: "signed_certificate_timestamp",
      tls13: "CH, CR, CT",
      ref: "[RFC6962]",
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
      ref: "[RFC9102][RFC Errata 6860]",
   },
   60: {
      name: "sequence_number_encryption_algorithms",
      tls13: "CH, HRR, SH",
      ref: "[draft-pismenny-tls-dtls-plaintext-sequence-number-01]",
   },
   61: { name: "rrc", tls13: "CH, SH", ref: "[draft-ietf-tls-dtls-rrc-10]" },
   64768: {
      name: "ech_outer_extensions",
      tls13: "CH [2]",
      ref: "[draft-ietf-tls-esni-17]",
   },
   65037: {
      name: "encrypted_client_hello",
      tls13: "CH, HRR, EE",
      ref: "[draft-ietf-tls-esni-17]",
   },
   65281: { name: "renegotiation_info", tls13: "-", ref: "[RFC5746]" },
};

const functions = {
   0: server_name,
   1: max_fragment_length,
   10: supported_groups,
   13: signature_algorithms,
   28: record_size_limit,
   43: supported_versions,
   44: cookie,
   51: key_share
};

export function extsBase(code, length, value) {
   const id = extsfull[code] ?? code;
   const data = functions[code]
      ? functions[code](value, length)
      : baseExt(value, length);
   return {
      id,
      data,
      length,
   };
}

function baseExt(value, length) {
   const sliced = value.sliceMovePos(length);
   return sliced;
}

/**
 * ! 3.  Server Name Indication
 * LINK - https://datatracker.ietf.org/doc/html/rfc6066#section-3
 */
function server_name(value) {
   const server_name_list = [];
   const payloadLength = value.uint16();
   const end = value.pos + payloadLength;
   while (true) {
      const typeCode = value.uint8();
      const hostType = typeCode == 0 ? "0-hostname" : `${typeCode}-unknown`;
      //if (typeCode !== 0) throw TypeError(`Expected code 0 but got ${typeCode}`);
      const payloadLength = value.uint16();
      const hostNameBytes = value.sliceMovePos(payloadLength);
      server_name_list.push({
         type: hostType,
         name: dec.decode(hostNameBytes),
      });
      if (value.pos >= end) break;
   }
   return server_name_list;
}

function max_fragment_length(value) {
   const types = Object.freeze({
      1: 2 ** 9,
      2: 2 ** 10,
      3: 2 ** 11,
      4: 2 ** 12,
   });
   const typeCode = value.uint8();
   if (typeCode < 1 || typeCode > 4) {
      throw TypeError(`Expected code between 1 to 4 but got ${typeCode}`);
   }
   return types[typeCode]
}

function record_size_limit(value) {
   return value.uint16()
}

function supported_groups(value) {
   const supportedGroups = []
   const payloadLength = value.uint16();
   const end = value.pos + payloadLength
   while (true) {
      const code = value.uint16();
      const group = namedGroup[code] ?? 'unknown'
      supportedGroups.push(`${uinToHex(code, 4)}-${group}`)
      if (value.pos >= end) break
   }
   return supportedGroups
}

function signature_algorithms(value) {
   const signatureAlgoritm = []
   const payloadLength = value.uint16();
   const end = value.pos + payloadLength
   while (true) {
      const code = value.uint16();
      const algo = SignatureScheme[code] ?? 'unknown';
      signatureAlgoritm.push(`${uinToHex(code, 4)}-${algo}`)
      if (value.pos >= end) break
   }
   return signatureAlgoritm
}

function supported_versions(value, length) {
   const isOdd = (length & 1) !== 0
   if (isOdd) {
      const versions = []
      const len = value.uint8();
      const end = value.pos + len;
      while (true) {
         const code = value.uint16();
         if (code < 0x0303) throw TypeError(`at least TLS 1.2-0x0303`);
         versions.push(`${uinToHex(code, 4)}-${tlsversions[code]}`)
         if (value.pos >= end) break
      }
      return versions;
   }
   const code = value.uint16();
   return `${uinToHex(code, 4)}-${tlsversions[code]}`
}

function cookie(value) {
   const len = value.uint16();
   const _cookie = value.sliceMovePos(len);
   return _cookie
}

function key_share(value) {
   if (value.type == 'client_hello') return keyShareClientHello(value)
   return keyShareEntry(value)
}

function keyShareClientHello(value) {
   const payloadLength = value.uint16();
   const end = value.pos + payloadLength
   const _keyShare = new Array(payloadLength);
   while (true) {
      _keyShare.push(keyShareEntry(value))
      if (value.pos >= end) break;
   }
   return _keyShare
}

function keyShareEntry(value) {
   const group = value.uint16();
   const keyLength = value.uint16();
   const keyShare = value.sliceMovePos(keyLength);
   return {
      name: `${group}-${namedGroup[group] ?? 'unknown'}`,
      key: keyShare
   }
}

var tlsversions = Object.freeze({
   0x0300: 'SSL 3.0',
   0x0301: 'TLS 1.0',
   0x0302: 'TLS 1.1',
   0x0303: 'TLS 1.2',
   0x0304: 'TLS 1.3'
})

var namedGroup = Object.freeze({
   /* Elliptic Curve Groups (ECDHE) */
   23: 'secp256r1',
   24: 'secp384r1',
   25: 'secp521r1',
   29: 'x25519',
   30: 'x448',
   /* Finite Field Groups (DHE) */
   256: 'ffdhe2048',
   257: 'ffdhe3072',
   258: 'ffdhe4096',
   259: 'ffdhe6144',
   260: 'ffdhe8192',
   /*0xFFFF-16 bytes-max*/
})

export var SignatureScheme = Object.freeze({
   /* RSASSA-PKCS1-v1_5 algorithms */
   0x0401: "rsa_pkcs1_sha256",
   0x0501: "rsa_pkcs1_sha384",
   0x0601: "rsa_pkcs1_sha512",

   /* ECDSA algorithms */
   0x0403: "ecdsa_secp256r1_sha256",
   0x0503: "ecdsa_secp384r1_sha384",
   0x0603: "ecdsa_secp521r1_sha512",

   /* RSASSA-PSS algorithms with public key OID rsaEncryption */
   0x0804: "rsa_pss_rsae_sha256",
   0x0805: "rsa_pss_rsae_sha384",
   0x0806: "rsa_pss_rsae_sha512",

   /* EdDSA algorithms */
   0x0807: "ed25519",
   0x0808: "ed448",

   /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
   0x0809: "rsa_pss_pss_sha256",
   0x080A: "rsa_pss_pss_sha384",
   0x080B: "rsa_pss_pss_sha512",

   /* Legacy algorithms */
   0x0201: "rsa_pkcs1_sha1",
   0x0203: "ecdsa_sha1",
   /*0xFFFF - 16 bytes - max*/
})