package com.example.keystorecrypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.sample.biometric.auth.CryptoHelper
import java.lang.Byte
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.security.*


class KeystoreManager(ctxt: Context, crypto: CryptoHelper) {
    private val IV_SIZE = 16
    private val KEY_SIZE = 256
    private val MASTER_KEY_ALIAS = "SYMMETRIC_MASTER_KEY"
    private val MASTER_ASYM_KEY_ALIAS = "ASYMMETRIC_MASTER_KEY"
    private val SHARED_PREFERENCES_NAME = "KeyStoreSettings"
    private val KEYSTORE_IV_NAME = "KeyStoreIV"
    private var applicationContext : Context
    private var cryptoHelper : CryptoHelper

    init {
        applicationContext = ctxt
        cryptoHelper = crypto
    }

    fun generateMasterKeys(){
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        if (!ks.containsAlias(MASTER_KEY_ALIAS))
            generateSymmetricKey()
        if (!ks.containsAlias(MASTER_ASYM_KEY_ALIAS))
            generateAsymmetricKeys()
    }

    private fun generateAsymmetricKeys(){
        val keyGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )

        val builder = KeyGenParameterSpec.Builder(MASTER_ASYM_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
                .setDigests(
                        KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512
                )
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
                    .setIsStrongBoxBacked(true)
        }

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }

        keyGenerator.initialize(builder.build())
        keyGenerator.generateKeyPair()
    }

    private fun generateSymmetricKey(){
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)            // these methods require API min 28
                    .setIsStrongBoxBacked(true)
        }

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true)  // this method requires API min 24
        }
        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    fun getLocalEncryptionCipher():Cipher {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val key = ks.getKey(MASTER_KEY_ALIAS, null)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val preferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        var iv : kotlin.ByteArray
        if (preferences.contains(KEYSTORE_IV_NAME)){
            iv = cryptoHelper.hexToByteArray(preferences.getString(KEYSTORE_IV_NAME, "")!!)
            val spec = GCMParameterSpec(IV_SIZE * Byte.SIZE, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            return cipher
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, cipher.parameters)
            val editor = preferences.edit()
            editor.putString(KEYSTORE_IV_NAME, cryptoHelper.byteArrayToHex(cipher.iv))
            editor.apply()
            return cipher
        }
    }

    fun encryptApplicationKey(pt: ByteArray, cipher: Cipher): ByteArray {
        return cipher.doFinal(pt)?: throw IllegalArgumentException("ENCRYPTION ERROR!")
    }

    fun decryptApplicationKey(ct: ByteArray, cipher: Cipher): ByteArray {
        return cipher.doFinal(ct)?: throw IllegalArgumentException("DECRYPTION ERROR!")
    }

    fun getSignature(): Signature {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val key = ks.getKey(MASTER_ASYM_KEY_ALIAS, null) as PrivateKey
        val signature = Signature.getInstance("SHA512withECDSA")
        signature.initSign(key)
        return signature
    }

    fun verifySignature(dataSigned: ByteArray, data: ByteArray): Boolean {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val certificate = ks.getCertificate(MASTER_ASYM_KEY_ALIAS)
        val signature = Signature.getInstance("SHA512withECDSA")
        signature.initVerify(certificate)
        signature.update(data)
        return signature.verify(dataSigned)
    }
}