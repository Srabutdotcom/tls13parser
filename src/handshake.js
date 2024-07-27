import { Extension } from "./extension.js";
import { SignatureScheme, extsBase, extsfull } from "./extsfull.js";
import { ensureUint8View, uinToHex } from "./tools.js";

const handShakes = Object.freeze({
   0: "HelloRequest", //RESERVED
   1: ClientHello,
   2: ServerHello,
   4: NewSessionTicket,
   8: EncryptedExtensions, //(TLS 1.3 only)
   11: Certificate,
   12: "ServerKeyExchange", //RESERVED
   13: CertificateRequest,
   14: "ServerHelloDone", //RESERVED
   15: CertificateVerify,
   16: "ClientKeyExchange", //RESERVED
   20: Finished,
});

export function Handshake(_value, pos) {
   const value = ensureUint8View(_value, pos)
   const typeCode = value.uint8();
   const typeFunc = typeof handShakes[typeCode]=='string'? genericHandshake:handShakes[typeCode] ;
   const name = typeof handShakes[typeCode]=='string' ? handShakes[typeCode]: typeFunc.name;
   const payloadLength = value.uint24(); // 24 bytes
   return {
      length: payloadLength,
      [name]: typeFunc(value, payloadLength, name),
      value
   }
   //this[this.type] = clientHello(value, this.payloadLength) 
}

export class _Handshake {

   #value;
   constructor(value, length) {
      this.#value = value;
      this.length = length;
      const typeCode = this.#value.uint8();
      this.type = handShakes[typeCode];
      if (!this.type) {
         throw TypeError(`Unexpected type of record value ${typeCode}`);
      }
      this.payloadLength = this.#value.uint24(); // 24 bytes
      this[this.type] = ClientHello(value, this.payloadLength)
      //this.handshake = new this.type(this.#value, this.payloadLength);
   }
   get pos() {
      return this.#value.pos;
   }
   get value() {
      return this.#value;
   }
}

const cipherEnums = Object.freeze({
   0x1301: "TLS_AES_128_GCM_SHA256",
   0x1302: "TLS_AES_256_GCM_SHA384",
   0x1303: "TLS_CHACHA20_POLY1305_SHA256",
   0x1304: "TLS_AES_128_CCM_SHA256",
   0x1305: "TLS_AES_128_CCM_8_SHA256",
});

function sessionId(value) {
   const length = value.uint8(); //*8 bytes
   if (length == 0) return;
   const _sessionId = value.sliceMovePos(length);
   return _sessionId;
}

function extension(value) {
   const length = value.uint16(); //*16 bytes
   if (length == 0) throw TypeError(`must have extension`);
   const exts = {
      length,
   };
   //this.extension = new Extension(this, length)
   const end = length + value.pos;
   while (true) {
      const typeCode = value.uint16(); //*uint16
      const typeFull = extsfull[typeCode] ?? { name: typeCode };
      const length = value.uint16(); //*uint16
      exts[typeFull.name] = extsBase(typeCode, length, value);
      //console.dir(exts[typeFull.name]);
      if (value.pos >= end) break;
   }
   return exts
}

export function ServerHello(value, length, type = 'server_hello') {
   value.type = 'server_hello'
   const versionCode = value.uint16();
   if (versionCode !== 0x0303) {
      throw TypeError(
         `Expected protocolVersion 0x0303 but got ${uinToHex(versionCode, 4)}`,
      );
   }
   const version = `${uinToHex(versionCode, 4)}-TLS 1.2 (legacy protocol version)`;
   const random = value.sliceMovePos(32);

   const session_id = sessionId(value);
   const cipherCode = value.uint16();
   const cipher_suite = `${uinToHex(cipherCode, 4)}-${cipherEnums[cipherCode]}`
   const compression_method = value.uint8();
   const extensions = extension(value)

   return {
      length,
      version,
      random,
      session_id,
      cipher_suite,
      compression_method,
      extensions
   }
}

export function ClientHello(value, length) {
   value.type = 'client_hello'
   const versionCode = value.uint16();
   if (versionCode !== 0x0303) {
      throw TypeError(
         `Expected protocolVersion 0x0303 but got ${uinToHex(versionCode, 4)}`,
      );
   }
   const version = `${uinToHex(versionCode, 4)}-TLS 1.2 (legacy protocol version)`;
   const random = value.sliceMovePos(32);

   const session_id = sessionId(value);
   const cipher_suites = cipherSuites(value);
   const compression_methods = compression(value);
   const extensions = extension(value)

   return {
      length,
      version,
      random,
      session_id,
      cipher_suites,
      compression_methods,
      extensions
   }

   function cipherSuites(value) {
      const ciphers = [];
      const length = value.uint16(); //*16 bytes
      if (length == 0) throw TypeError(`at least one cipherSuite list`);
      const end = value.pos + length;
      while (true) {
         const code = value.uint16();
         //const desc = cipherEnums[code];
         ciphers.push(
            code
            //`${uinToHex(code, 4)}-${desc}`,
         );
         if (value.pos >= end) break;
      }
      return ciphers;
   }

   function compression(value) {
      const length = value.uint8(); //*8 bytes
      if (length == 0) throw TypeError(`compression must have 1 length`);
      const code = value.uint8(); //*8 bytes
      if (code !== 0) {
         throw TypeError(`expected compression code 0 but got ${code}`);
      }
      return `${uinToHex(code, 2)}-No Compression`;
   }

}

export class _ClientHello {
   #cipherEnums = Object.freeze({
      0x1301: "TLS_AES_128_GCM_SHA256",
      0x1302: "TLS_AES_256_GCM_SHA384",
      0x1303: "TLS_CHACHA20_POLY1305_SHA256",
      0x1304: "TLS_AES_128_CCM_SHA256",
      0x1305: "TLS_AES_128_CCM_8_SHA256",
   });
   #value;
   version;
   random;
   sessionId;
   ciphers = [];
   compression;
   constructor(value, length) {
      this.#value = value;
      this.length = length;
      const versionCode = this.#value.uint16();
      if (versionCode !== 0x0303) {
         throw TypeError(
            `Expected protocolVersion 0x0303 but got ${Number(versionCode).toString(16).padStart(6, "0x0000")
            }`,
         );
      }
      this.version = `${uinToHex(versionCode, 4)}-TLS 1.2 (legacy protocol version)`;
      this.random = this.#value.sliceMovePos(32);

      this.#sessionId(); //* parse sessionId (if any)
      this.#cipherSuites(); //* parse cipherSuites, at least one cipherSuite
      this.#compression(); //* parse compression
      this.#extension(); //* parse extensions
   }
   #sessionId() {
      const length = this.#value.uint8(); //*8 bytes
      if (length == 0) return;
      this.sessionId = this.#value.sliceMovePos(length);
   }
   #cipherSuites() {
      const length = this.#value.uint16(); //*16 bytes
      if (length == 0) throw TypeError(`at least one cipherSuite list`);
      const end = this.#value.pos + length;
      while (true) {
         const code = this.#value.uint16();
         //const desc = this.#cipherEnums[code];
         this.ciphers.push(
            code
            //`${uinToHex(code, 4)}-${desc}`,
         );
         if (this.#value.pos >= end) break;
      }
   }
   #compression() {
      const length = this.#value.uint8(); //*8 bytes
      if (length == 0) throw TypeError(`compression must have 1 length`);
      const code = this.#value.uint8(); //*8 bytes
      if (code !== 0) {
         throw TypeError(`expected compression code 0 but got ${code}`);
      }
      this.compression = `${uinToHex(code, 4)}-No Compression`;
   }
   #extension() {
      const length = this.#value.uint16(); //*16 bytes
      if (length == 0) throw TypeError(`must have extension`);
      this.extension = {
         length,
      };
      //this.extension = new Extension(this, length)
      this.#parseExt();
   }
   #parseExt() {
      const end = this.extension.length + this.#value.pos;
      while (true) {
         const typeCode = this.value.uint16(); //*uint16
         const typeFull = extsfull[typeCode] ?? { name: typeCode };
         const length = this.value.uint16(); //*uint16
         this.extension[typeFull.name] = extsBase(typeCode, length, this);
         //console.log(this.extension[typeFull.name]);
         if (this.#value.pos >= end) break;
      }
   }
   get value() {
      return this.#value;
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
   }
}
function EncryptedExtensions(value, length) {
   const len = value.uint16();
   return value.sliceMovePos(len);
}

function Certificate(value, length) {
   let len = value.uint8();
   const certificate_request_context = value.sliceMovePos(len);
   len = value.uint24();
   const certificate_list = CertificateEntry(value, len)
   return {
      certificate_request_context,
      certificate_list//FIXME - 
   }
}

function CertificateEntry(value, length) {
   let len = value.uint24();
   const certificate = value.sliceMovePos(len);
   len = value.uint16();
   const extensions = value.sliceMovePos(len)
   return {
      certificate,
      extensions
   }
}

function CertificateRequest(value, length) {
   let len = value.uint8();
   const certificate_request_context = value.sliceMovePos(len);
   len = value.uint16();
   const extensions = value.sliceMovePos(len);
   return {
      certificate_request_context,
      extensions
   }
}

function CertificateVerify(value, length) {
   const sigCode = value.uint16();
   const signatureAlgoritm = `${uinToHex(sigCode, 4)}-${SignatureScheme[sigCode]}`
   const len = value.uint16();
   const signature = value.sliceMovePos(len);
   return {
      signatureAlgoritm,
      signature
   }
}

function Finished(value, length) {
   const verify_data = value.sliceMovePos(length);
   return {
      verify_data
   }
}

function genericHandshake(value, length, type){
   //if(type == "HelloRequest")return ServerHello(value, length, type)
   value.type = type;
   return value.sliceMovePos(length);
}

