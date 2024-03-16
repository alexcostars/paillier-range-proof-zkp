const paillier = require('paillier-js')
const { encryptWithProof, verifyProof } = require('./paillier-range-proof')
const util = require('util')

const bits = 128
const {publicKey, privateKey} = paillier.generateRandomKeys(bits)

const validRange = [41, 48468, 15, 184]
const value = 184
const [cipher, proof] = encryptWithProof(publicKey, value, validRange, bits)

console.log("proof: ", util.inspect(proof, {showHidden: false, depth: null, colors: true}))

//send cipher and proof to the verifier

const result = verifyProof(publicKey, cipher, proof, validRange)
console.log(`is cipher into [${validRange}]? ${result}`)
