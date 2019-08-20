package com.example.keystorecrypto

import com.sample.biometric.auth.CryptoHelper
import javax.crypto.Cipher
import android.content.Context.MODE_PRIVATE
import android.content.Context
import java.security.Signature


class SecureLocalManager(ctxt: Context) {
    companion object {
        const val SHARED_PREFERENCES_NAME = "settings"
        const val APPLICATION_KEY_NAME = "ApplicationKey"
        const val APPLICATION_IV_NAME = "ApplicationKeyIV"
        const val SECRET_TEXT_NAME = "Secret"
    }

    private var keystoreManager: KeystoreManager
    private var cryptoHelper: CryptoHelper
    private lateinit var applicationKey : ByteArray
    private lateinit var iv : ByteArray
    private var applicationContext : Context

    init {
        applicationContext = ctxt
        cryptoHelper = CryptoHelper()
        keystoreManager = KeystoreManager(applicationContext, cryptoHelper)
        keystoreManager.generateMasterKeys()
    }


    fun encryptLocalData(data: ByteArray):ByteArray {
        return cryptoHelper.encryptData(data, applicationKey, iv)
    }

    fun decryptLocalData(data: ByteArray):ByteArray {
        return cryptoHelper.decryptData(data, applicationKey, iv)
    }

    fun getLocalEncryptionCipher():Cipher{
        return keystoreManager.getLocalEncryptionCipher()
    }

    fun loadOrGenerateApplicationKey(cipher: Cipher){
        val preferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, MODE_PRIVATE)
        if (preferences.contains(APPLICATION_KEY_NAME)) {
            val encryptedAppKey = preferences.getString(APPLICATION_KEY_NAME, "")!!
            applicationKey = keystoreManager.decryptApplicationKey(cryptoHelper.hexToByteArray(encryptedAppKey), cipher)
            iv = cryptoHelper.hexToByteArray(preferences.getString(APPLICATION_IV_NAME, "")!!)
        }
        else{
            applicationKey = cryptoHelper.generateApplicationKey()
            iv = cryptoHelper.generateIV()
            val editor = preferences.edit()
            val encryptedAppKey = cryptoHelper.byteArrayToHex(keystoreManager.encryptApplicationKey(applicationKey, cipher))
            editor.putString(APPLICATION_KEY_NAME, encryptedAppKey)
            editor.putString(APPLICATION_IV_NAME, cryptoHelper.byteArrayToHex(iv))
            editor.apply()
        }
    }

    fun getSignature(): Signature {
        return keystoreManager.getSignature()
    }

    fun signData(data: ByteArray, signature: Signature): ByteArray {
        signature.update(data)
        return signature.sign()
    }

    fun verifyDataSignature(dataSigned: ByteArray, data: ByteArray): Boolean {
        return keystoreManager.verifySignature(dataSigned, data)
    }
}