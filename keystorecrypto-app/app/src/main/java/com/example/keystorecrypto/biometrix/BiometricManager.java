package com.example.keystorecrypto.biometrix;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.DialogInterface;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.support.annotation.NonNull;

import java.security.Signature;

import javax.crypto.Cipher;

public class BiometricManager extends BiometricManagerV23 {


    protected BiometricManager(final BiometricBuilder biometricBuilder) {
        this.context = biometricBuilder.context;
        this.title = biometricBuilder.title;
        this.subtitle = biometricBuilder.subtitle;
        this.description = biometricBuilder.description;
        this.negativeButtonText = biometricBuilder.negativeButtonText;
        this.cipher = biometricBuilder.cipher;
        this.signature = biometricBuilder.signature;
    }

    public void authenticate(@NonNull final BiometricCallback biometricCallback) {

        if(title == null) {
            biometricCallback.onBiometricAuthenticationInternalError("Biometric Dialog title cannot be null");
        }


        if(subtitle == null) {
            biometricCallback.onBiometricAuthenticationInternalError("Biometric Dialog subtitle cannot be null");
        }


        if(description == null) {
            biometricCallback.onBiometricAuthenticationInternalError("Biometric Dialog description cannot be null");
        }

        if(negativeButtonText == null) {
            biometricCallback.onBiometricAuthenticationInternalError("Biometric Dialog negative button text cannot be null");
        }


        if(!BiometricUtils.isSdkVersionSupported()) {
            biometricCallback.onSdkVersionNotSupported();
        }

        if(!BiometricUtils.isPermissionGranted(context)) {
            biometricCallback.onBiometricAuthenticationPermissionNotGranted();
        }

        if(!BiometricUtils.isHardwareSupported(context)) {
            biometricCallback.onBiometricAuthenticationNotSupported();
        }

        if(!BiometricUtils.isFingerprintAvailable(context)) {
            biometricCallback.onBiometricAuthenticationNotAvailable();
        }

        displayBiometricDialog(biometricCallback);
    }



    private void displayBiometricDialog(BiometricCallback biometricCallback) {
        if(BiometricUtils.isBiometricPromptEnabled()) {
            displayBiometricPrompt(biometricCallback);
        } else {
            displayBiometricPromptV23(biometricCallback);
        }
    }



    @TargetApi(Build.VERSION_CODES.P)
    private void displayBiometricPrompt(final BiometricCallback biometricCallback) {
        new BiometricPrompt.Builder(context)
                .setTitle(title)
                .setSubtitle(subtitle)
                .setDescription(description)
                .setNegativeButton(negativeButtonText, context.getMainExecutor(), new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        biometricCallback.onAuthenticationCancelled();
                    }
                })
                .build()
                .authenticate(new CancellationSignal(), context.getMainExecutor(),
                        new BiometricCallbackV28(biometricCallback));
    }


    public static class BiometricBuilder {

        private String title;
        private String subtitle;
        private String description;
        private String negativeButtonText;
        private Cipher cipher;
        private Signature signature;

        private Context context;
        public BiometricBuilder(Context context) {
            this.context = context;
        }

        public BiometricBuilder setTitle(@NonNull final String title) {
            this.title = title;
            return this;
        }

        public BiometricBuilder setSubtitle(@NonNull final String subtitle) {
            this.subtitle = subtitle;
            return this;
        }

        public BiometricBuilder setDescription(@NonNull final String description) {
            this.description = description;
            return this;
        }

        public BiometricBuilder setNegativeButtonText(@NonNull final String negativeButtonText) {
            this.negativeButtonText = negativeButtonText;
            return this;
        }

        public BiometricBuilder setCipher(@NonNull final Cipher c){
            this.cipher = c;
            return this;
        }

        public BiometricBuilder setSignature(@NonNull final Signature s){
            this.signature = s;
            return this;
        }

        public BiometricManager build() {
            return new BiometricManager(this);
        }
    }
}
