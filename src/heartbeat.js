/**!SECTION
 * LINK - https://datatracker.ietf.org/doc/html/rfc6520#autoid-6
 */

export function Heartbeat(value, length) {
   const typeCode = value.uint8()
   if (!typeCode) throw TypeError(`unexpected heartbeat type ${typeCode}`)
   const type = types[typeCode]
   const payloadLength = value.uint16();
   const message = value.slice(payloadLength);
   const paddingLength = length - payloadLength - 3;
   if (paddingLength < 16) throw TypeError(`padding length must be at least 16 bytes`)
   return {
      type,
      message
   }
}

export class _Heartbeat {
   #value
   constructor(value, length) {
      this.#value = value
      this.length = length;
      const typeCode = this.#value.uint8()
      this.type = types[typeCode]
      if (!this.type) throw TypeError(`unexpected heartbeat type ${typeCode}`)
      this.payloadLength = this.#value.uint16()//*uint16
      this.message = this.#value.slice(this.payloadLength);
      const paddingLength = this.length - this.payloadLength - 3;
      if (paddingLength < 16) throw TypeError(`padding length must be at least 16 bytes`)
   }
   get pos() { return this.#value.pos }
   get value() { return this.#value }
}

var types = Object.freeze({
   1: 'request',
   2: 'response'
   /*255:max value*/
})