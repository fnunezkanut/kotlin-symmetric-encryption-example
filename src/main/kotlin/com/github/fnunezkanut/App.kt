package com.github.fnunezkanut


fun main() {

    val key = "correct horse battery staple"
    println("supersecretkey: $key")

    val plaintext = "attack at dawn"
    val symmetricEncryption = SymmetricEncryption()
    println("plaintext: $plaintext")

    //encode
    val encrypted = symmetricEncryption.encrypt(
        plaintext = plaintext,
        secret = key
    )
    println("encrypted: $encrypted")

    //decode
    val decrypted = symmetricEncryption.decrypt(
        ciphertext = encrypted,
        secret = key
    )
    println("decrypted: $decrypted")
}
