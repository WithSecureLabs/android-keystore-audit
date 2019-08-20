package com.example.keystorecrypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.lang.Byte
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

class KeyStoreHelper(val TYPE:Type) {
    private val MASTER_KEY_ALIAS = "MASTER_KEY"
    enum class Type{
        SYMMETRIC,
        ASYMMETRIC,
    }

    fun generateMasterKey(){
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        if (ks.containsAlias(MASTER_KEY_ALIAS)) return
        if(TYPE == Type.ASYMMETRIC){
            val keyGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
            )
            keyGenerator.initialize(
                KeyGenParameterSpec.Builder(MASTER_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setDigests(
                        KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512
                    )
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setUserAuthenticationRequired(true)
                    .build()
            )
            keyGenerator.generateKeyPair()
        }else{
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(
                KeyGenParameterSpec.Builder(MASTER_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setUserAuthenticationRequired(true)
                    .build()
            )
            keyGenerator.generateKey()
        }

    }


    fun getCipher():Cipher{
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val key = ks.getKey(MASTER_KEY_ALIAS, null) as PrivateKey
        val cipher = if (TYPE == Type.ASYMMETRIC) Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        else Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key)
        return cipher
    }

    fun encryptApplicationKey(pt: ByteArray): ByteArray {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val key = ks.getCertificate(MASTER_KEY_ALIAS).publicKey
/*        val unrestrictedPublicKey = KeyFactory
            .getInstance(key.algorithm)
            .generatePublic(X509EncodedKeySpec(key.encoded))*/
        if (TYPE == Type.ASYMMETRIC){
            val spec = OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA1,
                PSource.PSpecified.DEFAULT
            )
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            cipher.init(Cipher.ENCRYPT_MODE, key, spec)
            return cipher.doFinal(pt)?: throw IllegalArgumentException("ENCRYPTION ERROR!")
        }
        else{
            val iv = ByteArray(16)
            Random().nextBytes(iv)
            //TODO: save IV
            val spec = GCMParameterSpec(16 * Byte.SIZE, iv)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, spec)
            return cipher.doFinal(pt)?: throw IllegalArgumentException("ENCRYPTION ERROR!")
        }
    }

    fun decryptApplicationKey(ct: ByteArray, cipher: Cipher): ByteArray {
        return cipher.doFinal(ct)?: throw IllegalArgumentException("DECRYPTION ERROR!")
    }
}