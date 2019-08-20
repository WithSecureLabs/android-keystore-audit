package com.example.keystorecrypto

import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import com.example.keystorecrypto.biometrix.BiometricCallback
import com.example.keystorecrypto.biometrix.BiometricManager
import android.widget.Toast


class MainActivity : BiometricCallback, AppCompatActivity() {
    private val TAG = this.javaClass.name
    private lateinit var etSecret: EditText
    private lateinit var bAppLock: Button
    private lateinit var secureLocalManager: SecureLocalManager

    override fun onCreate(savedInstanceState: Bundle?){
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        etSecret = findViewById(R.id.secretEditText)
        secureLocalManager = SecureLocalManager(applicationContext)
        bAppLock = findViewById(R.id.bencrypt)
        bAppLock.setOnClickListener {
            authenticate()
        }
        isAppLocked()
    }

    fun isAppLocked(): Boolean {
        val preferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        return if (preferences.contains(SecureLocalManager.SECRET_TEXT_NAME)){
            bAppLock.text = "UNLOCK"
            etSecret.setText(preferences.getString(SecureLocalManager.SECRET_TEXT_NAME, ""))
            etSecret.isEnabled = false
            true
        } else{
            etSecret.isEnabled = true
            bAppLock.text = "LOCK"
            false
        }
    }

    fun encryptAndSaveData(toastEnabled:Boolean = true): String? {
        val encrypted = secureLocalManager.encryptLocalData(etSecret.text.toString().toByteArray())
        val b64 = Base64.encodeToString(encrypted, Base64.NO_WRAP)

        val preferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        val editor = preferences.edit()
        editor.putString(SecureLocalManager.SECRET_TEXT_NAME, b64)
        editor.apply()

        if (toastEnabled) {
            val toast = Toast.makeText(applicationContext, "Data successfully encrypted!", Toast.LENGTH_SHORT)
            toast.show()
        }
        return b64
    }

    fun loadAndDecryptData(): String?{
        val preferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        val encrypted = preferences.getString(SecureLocalManager.SECRET_TEXT_NAME, "")
        preferences.edit().remove(SecureLocalManager.SECRET_TEXT_NAME).commit()
        val decrypted = secureLocalManager.decryptLocalData(Base64.decode(encrypted, Base64.NO_WRAP))

        val toast = Toast.makeText(applicationContext, "Data successfully decrypted!\nNow you can now change and encrypt your secret.", Toast.LENGTH_SHORT)
        toast.show()

        return String(decrypted)

    }

    fun authenticate(){
        val cipher = secureLocalManager.getLocalEncryptionCipher()

        BiometricManager.BiometricBuilder(this@MainActivity)
            .setTitle("Authorise")
            .setSubtitle("Please, authorise yourself")
            .setDescription("This is needed to perform cryptographic operations.")
            .setNegativeButtonText("Cancel")
            .setCipher(cipher)
            .build()
            .authenticate(this@MainActivity)
    }

    fun signMessageWithBiometrics(){
        val signature = secureLocalManager.getSignature()

        BiometricManager.BiometricBuilder(this@MainActivity)
                .setTitle("Authorise")
                .setSubtitle("Please, authorise yourself to sign the message")
                .setDescription("This message can be used to authorise some action.")
                .setNegativeButtonText("Cancel")
                .setSignature(signature)
                .build()
                .authenticate(this@MainActivity)
    }

    override fun onAuthenticationSuccessful(result: FingerprintManagerCompat.AuthenticationResult) {
        val cipher = result.cryptoObject.cipher!!
        secureLocalManager.loadOrGenerateApplicationKey(cipher)
        if (isAppLocked()) {
            val pt = loadAndDecryptData()
            etSecret.setText(pt)
        } else {
            val ct = encryptAndSaveData()
            etSecret.setText(ct)
        }
        isAppLocked()
    }

    override fun onAuthenticationSuccessful(result: BiometricPrompt.AuthenticationResult) {
        val cipher = result.cryptoObject.cipher!!
        secureLocalManager.loadOrGenerateApplicationKey(cipher)
        if (isAppLocked()) {
            val pt = loadAndDecryptData()
            etSecret.setText(pt)
        } else {
            val ct = encryptAndSaveData()
            etSecret.setText(ct)
        }
        isAppLocked()
    }


    override fun onSdkVersionNotSupported() {
        val toast = Toast.makeText(applicationContext, "This type of authentication is not available on your device.", Toast.LENGTH_SHORT)
        toast.show()
    }

    override fun onBiometricAuthenticationNotSupported() {
        val toast = Toast.makeText(applicationContext, "This type of authentication is not available on your device.", Toast.LENGTH_SHORT)
        toast.show()
    }

    override fun onBiometricAuthenticationNotAvailable() {
        val toast = Toast.makeText(applicationContext, "This type of authentication is not available on your device.", Toast.LENGTH_SHORT)
        toast.show()
    }

    override fun onBiometricAuthenticationPermissionNotGranted() {
        val toast = Toast.makeText(applicationContext, "Permissions not granted.", Toast.LENGTH_SHORT)
        toast.show()
    }

    override fun onBiometricAuthenticationInternalError(error: String?) {
        val toast = Toast.makeText(applicationContext, "An authentication error occurred, please try again.", Toast.LENGTH_SHORT)
        toast.show()
    }

    override fun onAuthenticationFailed() {
        val toast = Toast.makeText(applicationContext, "An authentication error occurred, please try again.", Toast.LENGTH_SHORT)
        toast.show()
    }

    override fun onAuthenticationCancelled() {
        val toast = Toast.makeText(applicationContext, "Authentication cancelled.", Toast.LENGTH_SHORT)
        toast.show()
    }

    override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
        val toast = Toast.makeText(applicationContext, "The functionality is not implemented yet.", Toast.LENGTH_SHORT)
        toast.show()
    }

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
        val toast = Toast.makeText(applicationContext, "An authentication error occurred, please try again.", Toast.LENGTH_SHORT)
        toast.show()
    }
}