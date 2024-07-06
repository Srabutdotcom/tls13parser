import { Handshake } from "../src/handshake.js";
import { Record } from "../src/index.js";
import { Aead } from "./tools/aead.js";

const application = hexArrayStrtoBytes(`17 03 03 00 17 6b e0 2f 9d a7 c2 dc 9d de f5 6f 24 68 b9 0a df a2 51 01 ab 03 44 ae`)

function hexArrayStrtoBytes(hexArrayStr) {
   const hexArray = hexArrayStr.split(/\s/).filter(e => e.length > 0).map(e => Number('0x' + e));
   return new Uint8Array(hexArray)
}

const record = new Record(application);

const cipherspec = hexArrayStrtoBytes(`14 03 03 00 01 01`);

const recordCipher = new Record(cipherspec);

//Server Encrypted Extensions
const key = hexStrtoBytes(`9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f`)
const iv = hexStrtoBytes(`9563bc8b590f671f488d2da3`)
const recdata=hexStrtoBytes(`1703030017`)

function hexStrtoBytes(hexString) {
   // Use match with a regular expression for more concise splitting
   const bytePairs = hexString.match(/..?/g);
   // Use map to convert each pair to a number and create a Uint8Array directly
   return new Uint8Array(bytePairs.map(pair => parseInt('0x' + pair, 16)));
}

const aead = new Aead(key,iv,recdata,0);

const serverEncryptedExtensions = hexArrayStrtoBytes(`08 00 00 02 00 00 16`);
const encryptedExtensions = await aead.encrypt(serverEncryptedExtensions);
const decryptedExtensions = await aead.decrypt(encryptedExtensions);

const data = decryptedExtensions.slice(0,decryptedExtensions.length-1);
const handshake = Handshake(data,data.length)

const certificate = hexArrayStrtoBytes(`0b 00 03 2e 00 00 03 2a 00 03 25 30 82 03 21 30 82 02 09 a0 03 02 01 02 02 08 15 5a 92 ad c2 04 8f 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 22 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 0a 13 0a 45 78 61 6d 70 6c 65 20 43 41 30 1e 17 0d 31 38 31 30 30 35 30 31 33 38 31 37 5a 17 0d 31 39 31 30 30 35 30 31 33 38 31 37 5a 30 2b 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 1c 30 1a 06 03 55 04 03 13 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 c4 80 36 06 ba e7 47 6b 08 94 04 ec a7 b6 91 04 3f f7 92 bc 19 ee fb 7d 74 d7 a8 0d 00 1e 7b 4b 3a 4a e6 0f e8 c0 71 fc 73 e7 02 4c 0d bc f4 bd d1 1d 39 6b ba 70 46 4a 13 e9 4a f8 3d f3 e1 09 59 54 7b c9 55 fb 41 2d a3 76 52 11 e1 f3 dc 77 6c aa 53 37 6e ca 3a ec be c3 aa b7 3b 31 d5 6c b6 52 9c 80 98 bc c9 e0 28 18 e2 0b f7 f8 a0 3a fd 17 04 50 9e ce 79 bd 9f 39 f1 ea 69 ec 47 97 2e 83 0f b5 ca 95 de 95 a1 e6 04 22 d5 ee be 52 79 54 a1 e7 bf 8a 86 f6 46 6d 0d 9f 16 95 1a 4c f7 a0 46 92 59 5c 13 52 f2 54 9e 5a fb 4e bf d7 7a 37 95 01 44 e4 c0 26 87 4c 65 3e 40 7d 7d 23 07 44 01 f4 84 ff d0 8f 7a 1f a0 52 10 d1 f4 f0 d5 ce 79 70 29 32 e2 ca be 70 1f df ad 6b 4b b7 11 01 f4 4b ad 66 6a 11 13 0f e2 ee 82 9e 4d 02 9d c9 1c dd 67 16 db b9 06 18 86 ed c1 ba 94 21 02 03 01 00 01 a3 52 30 50 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 01 30 1f 06 03 55 1d 23 04 18 30 16 80 14 89 4f de 5b cc 69 e2 52 cf 3e a3 00 df b1 97 b8 1d e1 c1 46 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 59 16 45 a6 9a 2e 37 79 e4 f6 dd 27 1a ba 1c 0b fd 6c d7 55 99 b5 e7 c3 6e 53 3e ff 36 59 08 43 24 c9 e7 a5 04 07 9d 39 e0 d4 29 87 ff e3 eb dd 09 c1 cf 1d 91 44 55 87 0b 57 1d d1 9b df 1d 24 f8 bb 9a 11 fe 80 fd 59 2b a0 39 8c de 11 e2 65 1e 61 8c e5 98 fa 96 e5 37 2e ef 3d 24 8a fd e1 74 63 eb bf ab b8 e4 d1 ab 50 2a 54 ec 00 64 e9 2f 78 19 66 0d 3f 27 cf 20 9e 66 7f ce 5a e2 e4 ac 99 c7 c9 38 18 f8 b2 51 07 22 df ed 97 f3 2e 3e 93 49 d4 c6 6c 9e a6 39 6d 74 44 62 a0 6b 42 c6 d5 ba 68 8e ac 3a 01 7b dd fc 8e 2c fc ad 27 cb 69 d3 cc dc a2 80 41 44 65 d3 ae 34 8c e0 f3 4a b2 fb 9c 61 83 71 31 2b 19 10 41 64 1c 23 7f 11 a5 d6 5c 84 4f 04 04 84 99 38 71 2b 95 9e d6 85 bc 5c 5d d6 45 ed 19 90 94 73 40 29 26 dc b4 0e 34 69 a1 59 41 e8 e2 cc a8 4b b6 08 46 36 a0 00 00`)
const handshakeCertificate = Handshake(certificate, certificate.length)

const certificateVerify = hexArrayStrtoBytes(`0f 00 01 04 08 04 01 00 5c bb 24 c0 40 93 32 da a9 20 bb ab bd b9 bd 50 17 0b e4 9c fb e0 a4 10 7f ca 6f fb 10 68 e6 5f 96 9e 6d e7 d4 f9 e5 60 38 d6 7c 69 c0 31 40 3a 7a 7c 0b cc 86 83 e6 57 21 a0 c7 2c c6 63 40 19 ad 1d 3a d2 65 a8 12 61 5b a3 63 80 37 20 84 f5 da ec 7e 63 d3 f4 93 3f 27 22 74 19 a6 11 03 46 44 dc db c7 be 3e 74 ff ac 47 3f aa ad de 8c 2f c6 5f 32 65 77 3e 7e 62 de 33 86 1f a7 05 d1 9c 50 6e 89 6c 8d 82 f5 bc f3 5f ec e2 59 b7 15 38 11 5e 9c 8c fb a6 2e 49 bb 84 74 f5 85 87 b1 1b 8a e3 17 c6 33 e9 c7 6c 79 1d 46 62 84 ad 9c 4f f7 35 a6 d2 e9 63 b5 9b bc a4 40 a3 07 09 1a 1b 4e 46 bc c7 a2 f9 fb 2f 1c 89 8e cb 19 91 8b e4 12 1d 7e 8e d0 4c d5 0c 9a 59 e9 87 98 01 07 bb bf 29 9c 23 2e 7f db e1 0a 4c fd ae 5c 89 1c 96 af df f9 4b 54 cc d2 bc 19 d3 cd aa 66 44 85 9c`)

const handshakeCertificateVerify = Handshake(certificateVerify, certificateVerify.length)

const finished = hexArrayStrtoBytes(`14 00 00 30 7e 30 ee cc b6 b2 3b e6 c6 ca 36 39 92 e8 42 da 87 7e e6 47 15 ae 7f c0 cf 87 f9 e5 03 21 82 b5 bb 48 d1 e3 3f 99 79 05 5a 16 0c 8d bb b1 56 9c`)
const handshakeFinished = Handshake(finished, finished.length)

const sessionTicket = hexArrayStrtoBytes(`04 00 00 d5 00 00 1c 20 00 00 00 00 08 00 00 00 00 00 00 00 00 00 c0 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 00 49 56 44 41 54 41 49 56 44 41 54 41 00 41 45 53 cb 11 9d 4d bd 2a 21 ec c2 26 a6 09 0e e8 ca 58 df 09 03 9b 35 96 f4 de 79 98 0e a3 25 d5 14 62 5c 0c 21 c5 0f 03 26 1d c4 2c e7 c5 97 0c 4c 01 ea 33 1c ff c8 99 66 ef 54 8b e4 df 9a 8b a4 38 5b eb 86 80 fd 0b 78 df b8 e9 8e fc 8f cc d8 14 fe cd 1d 9b ce 89 ca 05 dc 28 c2 49 e5 bd 61 d0 3a 56 8f 9a 0a 46 fb fd 05 30 2d b6 b2 f7 a3 13 e3 32 67 bf 0b cb dc ec fb 04 a4 d8 2f 5a 69 45 1f 56 7a b5 19 9b b2 6c 5c f2 00 72 f0 45 03 73 02 8f e0 71 d4 f4 1d 8f 61 ae 02 4d 69 bb ae 4c 00 00`)
const handshakeSessionTicket = Handshake(sessionTicket, sessionTicket.length)

