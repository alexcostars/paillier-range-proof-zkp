const paillierBigint = require('paillier-bigint')
const { encryptWithProof, verifyProof } = require('./paillier-range-proof')
const util = require('util')

async function main() {
    const bits = 128
    const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(bits)

    const validRange = [41n, 48468n, 15n, 454n, 184n]
    const value = 15n
    const r = 76532n
    const [cipher, proof] = encryptWithProof(publicKey, value, validRange, r, bits)
    console.log(`cipher: ${cipher}`)

    console.log("proof: ", util.inspect(proof, {showHidden: false, depth: null, colors: true}))

    //send cipher and proof to the verifier

    const result = verifyProof(publicKey, cipher, proof, validRange)
    console.log(`is cipher into [${validRange}]? ${result}`)

}

main()