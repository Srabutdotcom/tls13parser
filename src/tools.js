/**
 * 
 * @param {Uint8Array} data 
 * @param {uint} pos 
 * @param {uint} length 
 * @returns {uint} The unsigned integer value, or throws an error if the provided data is not a byte array,
       the position is out of bounds, or the length is less than 1.
 */
export function getUint8BE(data, pos = 0, length = 1) {

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
      throw TypeError(`length is beyond data.length`)
   }

   // Use a loop to handle bytes of any length
   let output = 0;
   for (let i = pos; i < pos + length; i++) {
      output = (output << 8) | data[i];
   }

   return output;
}

export function getUint8(data, pos) {
   return getUint8BE(data, pos, 1);
}

export function getUint16(data, pos) {
   return getUint8BE(data, pos, 2);
}

export function getUint24(data, pos) {
   return getUint8BE(data, pos, 3);
}

export function getUint32(data, pos) {
   return getUint8BE(data, pos, 4);
}

export class Uint8View extends Uint8Array {
   #pos = 0;
   constructor(uint8Array) {
      super(uint8Array);
   }
   uint8() {
      const out = getUint8(this, this.#pos);
      this.#pos++
      return out;
   }
   uint16() {
      const out = getUint16(this, this.#pos);
      this.#pos += 2
      return out;
   }
   uint24() {
      const out = getUint24(this, this.#pos);
      this.#pos += 3
      return out;
   }
   uint32() {
      const out = getUint32(this, this.#pos);
      this.#pos += 4
      return out;
   }
   /**
    * return a section of Uint8Array with specified length, the position is already defined in Uint8View
    * @param {uint} length 
    * @returns {Uint8Array}
    */
   slice(length) {
      const copy = new Uint8Array(this.buffer)
      const out = length!==undefined ? copy.slice(this.#pos, this.#pos + length) : copy.slice(this.#pos)
      return out;
   }
   sliceMovePos(length){
      const o = this.slice(length);
      this.#pos+=length;
      return o
   }
   get pos() { return this.#pos }
   posAdd(uint) {
      this.#pos += uint
   }
}

export function ensureUint8View(value){
   if((value instanceof Uint8View)==false) return new Uint8View(value);
   return value
}

export function uinToHex(uint, length) {
   return Number(uint).toString(16).padStart(length + 2, `0x` + '0'.repeat(length))
}