import { Handshake } from "./handshake.js";
import { Alert } from "./alert.js";
import { Heartbeat } from "./heartbeat.js";
import { Uint8View, ensureUint8View, uinToHex } from "./tools.js";

export class Record { // TLSPlainText
   #value
   constructor(value) {
      this.#value = ensureUint8View(value);//new Uint8View(value);
      this.pos = this.#value.pos;
      const typeCode = this.#value.uint8()
      this.type = records[typeCode]?.name;
      if (!this.type) throw TypeError(`Unexpected type of record value ${typeCode}`)
      this.version = this.#value.uint16()// == 0x0303?'TLS 1.2 (legacy record version)':false;
      // version check ignored for compatibility purpose, 
      //if (this.version !== 0x0303) throw TypeError(`Unsupported or unknown version ${this.version}`);
      this.version = `${uinToHex(this.version, 4)}-TLS 1.x (legacy record version)`;
      this.length = this.#value.uint16();
      this[this.type] = records[typeCode](this.value, this.length)
      //this.record = new this.type(this.#value, this.length);
   }
   get value() { return this.#value }
   get header() { return (new Uint8Array.from(this.value)).slice(this.pos, 5) }
}

function Invalid(value, length) {
   return `Invalid`
}

class _Invalid {
   #value
   constructor(value, length) {
      this.#value = value
      this.length = length;
   }
   get pos() { return this.#value.pos }
   get value() { return this.#value }
}

function ChangeCipherSpec(value, length) {
   const code = value.uint8();
   if (code !== 1) throw TypeError(`unexpected value in ChangeCipherSpec`);
   return code
}
class _ChangeCipherSpec {
   #value
   constructor(value, length) {
      if (length !== 1) throw TypeError(`length must be 1 in ChangeCipherSpec`)
      this.#value = value
      this.length = length;
      this.code = this.#value.uint8();
      if (this.code !== 1) throw TypeError(`unexpected value in ChangeCipherSpec`)
   }
   get pos() { return this.#value.pos }
   get value() { return this.#value }
}

function Application(value, length) {
   const data = value.sliceMovePos(length);
   return data;
}

class _Application {
   #value
   constructor(value, length) {
      this.#value = value
      this.length = length;
   }
   get pos() { return this.#value.pos }
   get value() { return this.#value }
}

var records = Object.freeze({//this.prototype.ContentTypes = {
   0: Invalid,
   20: ChangeCipherSpec,
   21: Alert,
   22: Handshake,
   23: Application,
   24: Heartbeat,
   /* 255: 'Default' */
})

export function Records(value) {
   let records = []
   while (true) {
      const record = new Record(value);
      records.push(record);
      if (record.value.pos >= record.value.length) break
      value = record.value;
   }
   return records;
}

