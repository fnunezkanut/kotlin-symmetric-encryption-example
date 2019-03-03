package com.github.fnunezkanut

import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


/**
 * @author Fidel Nunez Kanut
 * two way symmetric encryption using 256 bit key + "AES/GCM/NoPadding"
 */
class SymmetricEncryption {


    //symmetric encryption constants for 256 bit AES/GCM/NoPadding
    private val algorithmName: String = "AES/GCM/NoPadding"
    private val algorithmNonceSize: Int = 12
    private val algorithmTagSize: Int = 128
    private val algorithmKeySize: Int = 256
    private val pbkdf2Name: String = "PBKDF2WithHmacSHA256"
    private val pbkdf2SaltSize: Int = 16
    private val pbkdf2Iterations = 32767


    fun encrypt(plaintext: String, secret: String): String {

        //generate a salt using a CSPRNG
        val rand = SecureRandom()
        val salt = ByteArray(pbkdf2SaltSize)
        rand.nextBytes(salt)

        //create an instance of PBKDF2 and derive a key.
        val pwSpec = PBEKeySpec(secret.toCharArray(), salt, pbkdf2Iterations, algorithmKeySize)
        val keyFactory: SecretKeyFactory = SecretKeyFactory.getInstance(pbkdf2Name)
        val key: ByteArray = keyFactory.generateSecret(pwSpec).encoded

        //encrypt and prepend salt.
        val ciphertextAndNonce: ByteArray = encryptByteArray(plaintext.toByteArray(StandardCharsets.UTF_8), key)
        val ciphertextAndNonceAndSalt = ByteArray(salt.size + ciphertextAndNonce.size)
        System.arraycopy(salt, 0, ciphertextAndNonceAndSalt, 0, salt.size)
        System.arraycopy(ciphertextAndNonce, 0, ciphertextAndNonceAndSalt, salt.size, ciphertextAndNonce.size)

        //ensure ciphertext is properly encoded
        return Base64.getEncoder().encodeToString(ciphertextAndNonceAndSalt)
    }

    fun decrypt(ciphertext: String, secret: String): String {

        //decode from base64
        val ciphertextAndNonceAndSalt: ByteArray = Base64.getDecoder().decode(ciphertext)

        //retrieve the salt and ciphertextAndNonce.
        val salt = ByteArray(pbkdf2SaltSize)
        val ciphertextAndNonce = ByteArray(ciphertextAndNonceAndSalt.size - pbkdf2SaltSize)
        System.arraycopy(ciphertextAndNonceAndSalt, 0, salt, 0, salt.size)
        System.arraycopy(ciphertextAndNonceAndSalt, salt.size, ciphertextAndNonce, 0, ciphertextAndNonce.size)

        //create an instance of PBKDF2 and derive the key.
        val pwSpec = PBEKeySpec(secret.toCharArray(), salt, pbkdf2Iterations, algorithmKeySize)
        val keyFactory: SecretKeyFactory = SecretKeyFactory.getInstance(pbkdf2Name)
        val key: ByteArray = keyFactory.generateSecret(pwSpec).encoded

        //decrypt and return result.
        return String(decryptByteArray(ciphertextAndNonce, key))
    }

    private fun encryptByteArray(plaintext: ByteArray, key: ByteArray): ByteArray {

        //generate a 96-bit nonce using a CSPRNG.
        val rand = SecureRandom()
        val nonce = ByteArray(algorithmNonceSize)
        rand.nextBytes(nonce)

        //create the cipher instance and initialize.
        val cipher: Cipher = Cipher.getInstance(algorithmName)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(algorithmTagSize, nonce))

        //encrypt and prepend nonce.
        val ciphertext: ByteArray = cipher.doFinal(plaintext)
        val ciphertextAndNonce = ByteArray(nonce.size + ciphertext.size)
        System.arraycopy(nonce, 0, ciphertextAndNonce, 0, nonce.size)
        System.arraycopy(ciphertext, 0, ciphertextAndNonce, nonce.size, ciphertext.size)

        return ciphertextAndNonce
    }

    private fun decryptByteArray(ciphertextAndNonce: ByteArray, key: ByteArray): ByteArray {

        //retrieve the nonce and ciphertext.
        val nonce = ByteArray(algorithmNonceSize)
        val ciphertext = ByteArray(ciphertextAndNonce.size - algorithmNonceSize)
        System.arraycopy(ciphertextAndNonce, 0, nonce, 0, nonce.size)
        System.arraycopy(ciphertextAndNonce, nonce.size, ciphertext, 0, ciphertext.size)

        //create the cipher instance and initialize.
        val cipher: Cipher = Cipher.getInstance(algorithmName)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(algorithmTagSize, nonce))

        //decrypt and return result.
        return cipher.doFinal(ciphertext)
    }
}