package com.github.fnunezkanut

import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class SymmetricEncryptionTest {


    @Test
    fun `two way encryption and decryption`() {

        //given
        val plaintext = "super secret info"
        val key = "SuperSecretKey1235676556"
        val se = SymmetricEncryption()

        //when
        val encrypted = se.encrypt(
            plaintext = plaintext,
            secret = key
        )
        val decrypted = se.decrypt(
            ciphertext = encrypted,
            secret = key
        )

        //then
        assertThat(decrypted).isEqualTo(plaintext)
    }
}