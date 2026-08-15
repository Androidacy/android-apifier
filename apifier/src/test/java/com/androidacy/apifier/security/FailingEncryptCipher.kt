/*
 * Copyright 2025 Androidacy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.androidacy.apifier.security

import java.security.AlgorithmParameters
import java.security.Key
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.CipherSpi

/**
 * Test-only AES/GCM cipher that decrypts normally and stops encrypting after a set number of
 * operations, standing in for a Keystore key that reads but cannot write. Registered ahead of the
 * platform providers for the duration of [withEncryptionFailingAfter], which is the only supported
 * entry point; [allowedEncryptions] is state shared through the JCE, so nested use is not allowed.
 */
object FailingEncryptCipher {

    const val PROVIDER_NAME = "ApifierTestFailingEncrypt"
    const val TRANSFORM = "AES/GCM/NoPadding"

    @Volatile
    @JvmStatic
    var allowedEncryptions: Int = Int.MAX_VALUE

    @Volatile
    @JvmStatic
    var encryptions: Int = 0

    fun <T> withEncryptionFailingAfter(allowed: Int, block: () -> T): T {
        allowedEncryptions = allowed
        encryptions = 0
        Security.insertProviderAt(FailingEncryptProvider(), 1)
        return try {
            block()
        } finally {
            Security.removeProvider(PROVIDER_NAME)
            allowedEncryptions = Int.MAX_VALUE
            encryptions = 0
        }
    }

    /** A platform cipher to delegate to, chosen without re-entering our own provider. */
    fun delegateCipher(): Cipher = Security.getProviders()
        .asSequence()
        .filter { it.name != PROVIDER_NAME }
        .mapNotNull { runCatching { Cipher.getInstance(TRANSFORM, it) }.getOrNull() }
        .firstOrNull()
        ?: error("no platform provider offers $TRANSFORM")
}

class FailingEncryptProvider : Provider(
    FailingEncryptCipher.PROVIDER_NAME,
    1.0,
    "test-only cipher that declines to encrypt"
) {
    init {
        put("Cipher.${FailingEncryptCipher.TRANSFORM}", FailingEncryptCipherSpi::class.java.name)
    }
}

/** Instantiated reflectively by the JCE, so it has to be public with a no-arg constructor. */
class FailingEncryptCipherSpi : CipherSpi() {

    private val delegate: Cipher = FailingEncryptCipher.delegateCipher()
    private var encrypting = false

    override fun engineSetMode(mode: String) = Unit

    override fun engineSetPadding(padding: String) = Unit

    override fun engineGetBlockSize(): Int = delegate.blockSize

    override fun engineGetOutputSize(inputLen: Int): Int = delegate.getOutputSize(inputLen)

    override fun engineGetIV(): ByteArray? = delegate.iv

    override fun engineGetParameters(): AlgorithmParameters? = delegate.parameters

    override fun engineInit(opmode: Int, key: Key, random: SecureRandom?) {
        encrypting = opmode == Cipher.ENCRYPT_MODE
        delegate.init(opmode, key, random)
    }

    override fun engineInit(
        opmode: Int,
        key: Key,
        params: AlgorithmParameterSpec?,
        random: SecureRandom?
    ) {
        encrypting = opmode == Cipher.ENCRYPT_MODE
        delegate.init(opmode, key, params, random)
    }

    override fun engineInit(
        opmode: Int,
        key: Key,
        params: AlgorithmParameters?,
        random: SecureRandom?
    ) {
        encrypting = opmode == Cipher.ENCRYPT_MODE
        delegate.init(opmode, key, params, random)
    }

    override fun engineUpdate(input: ByteArray, inputOffset: Int, inputLen: Int): ByteArray? =
        delegate.update(input, inputOffset, inputLen)

    override fun engineUpdate(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int
    ): Int = delegate.update(input, inputOffset, inputLen, output, outputOffset)

    override fun engineDoFinal(input: ByteArray?, inputOffset: Int, inputLen: Int): ByteArray {
        refuseWhenExhausted()
        return delegate.doFinal(input, inputOffset, inputLen)
    }

    override fun engineDoFinal(
        input: ByteArray?,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int
    ): Int {
        refuseWhenExhausted()
        return delegate.doFinal(input, inputOffset, inputLen, output, outputOffset)
    }

    // Failing here instead of at init keeps the JCE from silently retrying the next provider.
    private fun refuseWhenExhausted() {
        if (!encrypting) return
        if (FailingEncryptCipher.encryptions++ >= FailingEncryptCipher.allowedEncryptions) {
            throw IllegalStateException("encryption unavailable")
        }
    }
}
