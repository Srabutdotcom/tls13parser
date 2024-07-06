export function Alert(value, length) {
   const levelCode = value.uint8();
   const desCode = value.uint8();
   return {
      level :`${levelCode}-${levels[levelCode]}`,
      description : `${desCode}-${descriptions[desCode]}`
   }
}

export class _Alert {
   #value
   constructor(value, length) {
      this.#value = value
      this.length = length;
      this.level = levels[this.#value.at(this.#value.pos)]
      this.description = descriptions[this.#value.at(this.#value.pos + 1)]
   }
   get pos() { return this.#value.pos }
   get value() { return this.#value }
}

var descriptions = {
   0: 'close_notify',
   10: 'unexpected_message',
   20: 'bad_record_mac',
   21: 'decryption_failed_RESERVED',
   22: 'record_overflow',
   30: 'decompression_failure_RESERVED',
   40: 'handshake_failure',
   41: 'no_certificate_RESERVED',
   42: 'bad_certificate',
   43: 'unsupported_certificate',
   44: 'certificate_revoked',
   45: 'certificate_expired',
   46: 'certificate_unknown',
   47: 'illegal_parameter',
   48: 'unknown_ca',
   49: 'access_denied',
   50: 'decode_error',
   51: 'decrypt_error',
   60: 'export_restriction_RESERVED',
   70: 'protocol_version',
   71: 'insufficient_security',
   80: 'internal_error',
   86: 'inappropriate_fallback',
   90: 'user_canceled',
   100: 'no_renegotiation_RESERVED',
   109: 'missing_extension',
   110: 'unsupported_extension',
   111: 'certificate_unobtainable_RESERVED',
   112: 'unrecognized_name',
   113: 'bad_certificate_status_response',
   114: 'bad_certificate_hash_value_RESERVED',
   115: 'unknown_psk_identity',
   116: 'certificate_required',
   120: 'no_application_protocol',
   /*255*/
}

var levels = { 1: 'warning', 2: 'fatal' /*255*/ }