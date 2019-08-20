package com.sample.biometric.auth;

import android.content.Context
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class CryptoHelper {
    fun encryptData(data: ByteArray, applicationKey: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding") //actually uses PKCS#7
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(applicationKey, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    fun decryptData(data: ByteArray, applicationKey: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding") //actually uses PKCS#7
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(applicationKey, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    fun generateIV(size: Int=16): ByteArray {
        val random = SecureRandom()
        val iv = ByteArray(size)
        random.nextBytes(iv)
        return iv
    }

    fun generateApplicationKey(): ByteArray{
        val random = SecureRandom()
        val applicationKey = ByteArray(32)
        random.nextBytes(applicationKey)
        return applicationKey
    }

    fun byteArrayToHex(bytes: ByteArray) : String{
        val hexChars = "0123456789ABCDEF".toCharArray()
        val result = StringBuffer()

        bytes.forEach {
            val octet = it.toInt()
            val firstIndex = (octet and 0xF0).ushr(4)
            val secondIndex = octet and 0x0F
            result.append(hexChars[firstIndex])
            result.append(hexChars[secondIndex])
        }

        return result.toString()
    }

    fun hexToByteArray(hex: String) : ByteArray{
        val hexChars = "0123456789ABCDEF".toCharArray()
        val result = ByteArray(hex.length / 2)

        for (i in 0 until hex.length step 2) {
            val firstIndex = hexChars.indexOf(hex[i]);
            val secondIndex = hexChars.indexOf(hex[i + 1]);

            val octet = firstIndex.shl(4).or(secondIndex)
            result.set(i.shr(1), octet.toByte())
        }

        return result
    }
}
