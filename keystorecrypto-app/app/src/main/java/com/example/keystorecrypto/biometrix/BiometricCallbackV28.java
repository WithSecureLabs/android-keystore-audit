package com.example.keystorecrypto.biometrix;

import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.support.annotation.RequiresApi;


@RequiresApi(api = Build.VERSION_CODES.P)
public class BiometricCallbackV28 extends BiometricPrompt.AuthenticationCallback {

    private BiometricCallback biometricCallback;
    public BiometricCallbackV28(BiometricCallback biometricCallback) {
        this.biometricCallback = biometricCallback;
    }


    @Override
    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        biometricCallback.onAuthenticationSuccessful(result);
    }


    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);
        biometricCallback.onAuthenticationHelp(helpCode, helpString);
    }


    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
        biometricCallback.onAuthenticationError(errorCode, errString);
    }


    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        biometricCallback.onAuthenticationFailed();
    }
}
