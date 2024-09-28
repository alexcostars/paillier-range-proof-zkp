// source: https://github.com/framp/paillier-in-set-zkp/blob/master/index.js
// based on https://paillier.daylightingsociety.org/Paillier_Zero_Knowledge_Proof.pdf

const bigInt = require('big-integer')
const crypto = require('crypto')

const rand = (bitLength) => {
  let bytes = bitLength / 8
  let buf = Buffer.alloc(bytes)
  crypto.randomFillSync(buf)
  buf[0] = buf[0] | 128  // first bit to 1 -> to get the necessary bitLength
  return bigInt.fromArray([...buf], 256)
}

const getBase2Logarithm = (number, maxBits) => {
  // the same as Math.floor(Math.log2(number))
  let bits = bigInt(maxBits)
  while (true) {
    if(bigInt(2).pow(bits).leq(number)) {
      return bits
    }
    bits = bits.subtract(1)
  }
}

// getCoprime :: Bits -> Number -> Number
// Generate a coprime number of target (their GCD should be 1)
const getCoprime = (target, maxBits) => {
  const bits = getBase2Logarithm(target, maxBits)
  while (true) {
    const lowerBound = bigInt(2).pow(bits-1).plus(1)
    const size = bigInt(2).pow(bits).subtract(lowerBound)
    let possible = lowerBound.plus(rand(bits)).or(1)
    const result = bigInt(possible)
    if (possible.gt(bigInt(2).pow(1024))) return result
    while(target > 0) {
      [possible, target] = [target, bigInt(possible).mod(target)]
    }
    if (possible.eq(bigInt(1))) return result
  }
}

// encryptWithProof :: Paillier.PublickKey -> Message -> [Message] -> Bits
// Generate a message encryption and a Zero Knowledge proof that the message 
// is among a set of valid messages
const encryptWithProof = (publicKey, message, validMessages, r, bits=512) => {
  const as = []
  const es = []
  const zs = []

  const cipher = publicKey.encrypt(message, r)
  const _cipherBI = bigInt(cipher)
  const _n2BI = bigInt(publicKey._n2)
  const _gBI = bigInt(publicKey.g)

  const om = getCoprime(publicKey.n, bits)
  const ap = om.modPow(publicKey.n, publicKey._n2)

  let mi = null
  validMessages.forEach((mk, i) => {
    const gmk = _gBI.modPow(bigInt(mk), _n2BI)
    const uk = _cipherBI.times(gmk.modInv(_n2BI)).mod(_n2BI)
    if (message === mk) {
      as.push(ap)
      zs.push(null)
      es.push(null)
      mi = i
    } else {
      const zk = getCoprime(publicKey.n, bits)
      zs.push(zk)
      const ek = bigInt.randBetween(2, bigInt(2).pow(bits).subtract(1));
      es.push(ek)
      const zn = zk.modPow(publicKey.n, _n2BI)
      const ue = uk.modPow(ek, _n2BI)
      const ak = zn.times(ue.modInv(_n2BI)).mod(_n2BI)
      as.push(ak)
    }
  })

  const hash = crypto.createHash('sha256').update(as.join('')).digest('hex');

  const esum = es.filter(Boolean).reduce((acc, ek) => acc.plus(ek).mod(bigInt(2).pow(256)), bigInt(0))
  const ep = bigInt(hash, 16).subtract(esum).mod(bigInt(2).pow(256))
  const rep = bigInt(r).modPow(ep, publicKey.n)
  const zp = om.times(rep).mod(publicKey.n)
  es[mi] = ep
  zs[mi] = zp

  const proof = [as, es, zs]

  return [cipher, proof]
}

// verifyProof :: Paillier.PublickKEy -> Paillier.Encryption, -> Proof -> [Message] -> Bool
// Verify a Zero Knowledge proof that an encrypted message is among a set of valid messages
const verifyProof = (publicKey, cipher, [as, es, zs], validMessages) => {
  const hash = crypto.createHash('sha256').update(as.join('')).digest('hex');

  const us = validMessages.map(mk => {
    const gmk = bigInt(publicKey.g).modPow(mk, bigInt(publicKey._n2))
    const uk = bigInt(cipher).times(gmk.modInv(bigInt(publicKey._n2))).mod(bigInt(publicKey._n2))
    return uk
  })

  const esum = es.reduce((acc, ek) => acc.plus(ek).mod(bigInt(2).pow(256)), bigInt(0))
  if (!bigInt(hash, 16).eq(esum)) {
    return false
  }
  return zs.every((zk, i) => {
    const ak = as[i]
    const ek = es[i]
    const uk = us[i]
    const zkn = zk.modPow(publicKey.n, publicKey._n2)
    const uke = uk.modPow(ek, publicKey._n2)
    const akue = ak.times(uke).mod(publicKey._n2)
    return zkn.eq(akue)
  })
}

module.exports = {
  encryptWithProof,
  verifyProof,
}
