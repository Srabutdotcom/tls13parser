import { ClientHello } from "./handshake.js"
import { uinToHex } from "./tools.js"
import { extsBase, extsfull } from "./extsfull.js"

const dec = new TextDecoder
export class Extension {
   #types = {
      0: ServerName,//"server_name",
      1: MaxFragmentLength,//"max_fragment_length", /* 2: "client_certificate_url", 3: "trusted_ca_keys", 4: "truncated_hmac",  */
      5: StatusRequest,//"status_request", /* 6: "user_mapping", 7: "client_authz", 8: "server_authz", 9: "cert_type", */
      10: SupportedGroup,//"supported_groups", /* 11: "ec_point_formats", 12: "srp", */
      13: SignatureAlgorithm,//"signature_algorithms",
      14: UseSrtp,//"use_srtp",
      15: Heartbeat,//"heartbeat",
      16: ALPN,//"application_layer_protocol_negotiation", /* 17: "status_request_v2", */
      18: SignedCertTimeStamp,//"signed_certificate_timestamp",
      19: ClientCertType,//"client_certificate_type",
      20: ServerCertType,//"server_certificate_type",
      21: Padding,//"padding", /* 22: "encrypt_then_mac", 23: "extended_master_secret", 24: "token_binding", 25: "cached_info", 26: "tls_lts", 27: "compress_certificate", 28: "record_size_limit", 29: "pwd_protect", 30: "pwd_clear", 31: "password_salt", 32: "ticket_pinning", 33: "tls_cert_with_extern_psk", 34: "delegated_credential", 35: "session_ticket", 36: "TLMSP", 37: "TLMSP_proxying", 38: "TLMSP_delegate", 39: "supported_ekt_ciphers", */
      //40: "Reserved",
      41: PreSharedKey,//"pre_shared_key",
      42: EarlyData,//"early_data",
      43: SupportedVersion,//"supported_versions",
      44: Cookie,//"cookie",
      45: PskKeyExcMode,//"psk_key_exchange_modes",
      //46: "Reserved",
      47: CertAuths,//"certificate_authorities",
      48: OidFilters,//"oid_filters",
      49: PostHandshakeAuth,//"post_handshake_auth",
      50: SignAlgoCert,//"signature_algorithms_cert",
      51: KeyShare,//"key_share", /* 52: "transparency_info", 53: "connection_id_deprecated", 54: "connection_id", 55: "external_id_hash", 56: "external_session_id", 57: "quic_transport_parameters", 58: "ticket_request", 59: "dnssec_chain", 60: "sequence_number_encryption_algorithms", 61: "rrc" */
      /*65535-max*/
   }
   #parent
   #value
   #data
   #end
   extensions = []
   exts = {}
   constructor(parent, length) {
      this.#parent = parent;
      this.#value = parent.value;
      this.length = length;
      this.#end = this.#value.pos + length;
      this.#data = this.#value.slice(length);
      this.#parse();//* parse extensions
   }
   #parse() {
      while (true) {
         const typeCode = this.#value.uint16();//*uint16
         const type = this.#types[typeCode]?.name ?? typeCode
         const typeFull = extsfull[typeCode] ?? typeCode
         const length = this.#value.uint16();//*uint16
         this.extensions.push(
            this.#types[typeCode]?new this.#types[typeCode](this, length): new UnknownExt(this, length)
         ) 
         this.exts[typeFull.name] = extsBase(typeCode, length, this)
         if (this.#value.pos >= this.#end) break;
      }
   }
   get parent() { return this.#parent }
   get value() { return this.#value }
   get data() { return this.#data }
}

const namedGroup = Object.freeze({
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

class extensionBase {
   #parent
   #value
   #data
   #end
   constructor(parent, length) {
      this.#parent = parent
      this.#value = parent.value;
      this.length = length;
      this.#end = this.#value.pos + length;
      this.#data = this.#value.slice(length);
   }
   get parent() { return this.#parent }
   get data() { return this.#data }
   get value() { return this.#value }
   get end() { return this.#end }
}

class UnknownExt extends extensionBase {
   constructor(parent, length) {
      super(parent, length);
      this.value.posAdd(length);
   }
}

class ServerName extends extensionBase {
   /**
    * ! 3.  Server Name Indication
    * LINK - https://datatracker.ietf.org/doc/html/rfc6066#section-3
    */
   serverNameList = []
   constructor(parent, length) {
      super(parent, length)
      this.#parse() //* parse server_name_list<1...2^16-1>
   }
   #parse() {
      const length = this.value.uint16();
      const end = this.value.pos + length
      while (true) {
         const typeCode = this.value.uint8();
         if (typeCode !== 0) throw TypeError(`Expected code 0 but got ${typeCode}`);
         const payloadLength = this.value.uint16();
         const hostNameBytes = this.value.sliceMovePos(payloadLength); 
         this.serverNameList.push({ 'hostname': dec.decode(hostNameBytes) })
         if (this.value.pos >= end) break;
      }
   }
}

class MaxFragmentLength extends extensionBase {
   #types = Object.freeze({
      1: 2 ** 9,
      2: 2 ** 10,
      3: 2 ** 11,
      4: 2 ** 12
   })
   constructor(parent, length) {
      super(parent, length)
      const typeCode = this.value.uint8();
      this.maxFragmentLength = this.#types[typeCode];
      if (!this.maxFragmentLength) throw TypeError(`Expected code between 1 to 4 but got ${typeCode}`)
   }
}


class StatusRequest extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class SupportedGroup extends extensionBase {
   supportedGroups = []
   constructor(parent, length) {
      super(parent, length)
      this.payloadLength = this.value.uint16();
      this.#parse()
   }
   #parse() {
      while (true) {
         const code = this.value.uint16();
         const group = namedGroup[code] ?? 'unknown'
         this.supportedGroups.push(`${code}-${group}`)
         if (this.value.pos >= this.end) break
      }
   }
}

class SignatureAlgorithm extends extensionBase {
   #sigalgs = {
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
   }

   signatureAlgoritm = [];
   constructor(parent, length) {
      super(parent, length)
      this.payloadLength = this.value.uint16();
      this.#parse()
   }
   #parse() {
      while (true) {
         const code = this.value.uint16();
         const algo = this.#sigalgs[code] ?? 'unknown';
         this.signatureAlgoritm.push(`${uinToHex(code,4)}-${algo}`)
         if (this.value.pos >= this.end) break
      }
   }
}

class UseSrtp extends extensionBase {
   constructor(parent, length) {
      super(parent, length);
      this.value.posAdd(length)
   }
}

class Heartbeat extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class ALPN extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class SignedCertTimeStamp extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class ClientCertType extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class ServerCertType extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class Padding extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class PreSharedKey extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class EarlyData extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class SupportedVersion extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class Cookie extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class PskKeyExcMode extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class CertAuths extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class OidFilters extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class PostHandshakeAuth extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class SignAlgoCert extends extensionBase {
   constructor(parent, length) {
      super(parent, length)
      this.value.posAdd(length)
   }
}

class KeyShare extends extensionBase {
   constructor(parent, length) {
      super(parent, length); 
      if (parent.parent instanceof ClientHello) {
         const payloadLength = this.value.uint16();
         const end = this.value.pos + payloadLength
         this.keyShareClientHello = new Array(payloadLength);
         while (true) {
            const group = this.value.uint16();
            const keyLength = this.value.uint16();
            const keyShare = this.value.sliceMovePos(keyLength); 
            this.keyShareClientHello.push({
               name: `${group}-${namedGroup[group]??'unknown'}`,
               key: keyShare
            })
            if(this.value.pos >= end)break;
         }
      } else {
         const group = this.value.uint16();
         const keyLength = this.value.uint16();
         const keyShare = this.value.sliceMovePos(keyLength); 
         this.keyShareServerHello = { 
            name: group,
            key: keyShare
         }
      }
   }
}





