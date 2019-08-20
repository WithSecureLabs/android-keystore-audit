package com.example.keystorecrypto.biometrix;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v4.os.CancellationSignal;
import com.example.keystorecrypto.R;

import java.security.Signature;

import javax.crypto.Cipher;


@TargetApi(Build.VERSION_CODES.M)
public class BiometricManagerV23 {
    private final String TAG = this.getClass().getName();

    private FingerprintManagerCompat.CryptoObject cryptoObject;

    protected Cipher cipher;
    protected Signature signature;
    protected Context context;
    protected String title;
    protected String subtitle;
    protected String description;
    protected String negativeButtonText;
    private BiometricDialogV23 biometricDialogV23;


    public void displayBiometricPromptV23(final BiometricCallback biometricCallback) {

        if (cipher != null)
            cryptoObject = new FingerprintManagerCompat.CryptoObject(cipher);
        else if (signature != null)
            cryptoObject = new FingerprintManagerCompat.CryptoObject(signature);
        else
            throw new UnsupportedOperationException("The type of CryptoObject is not supported yet.");

        FingerprintManagerCompat fingerprintManagerCompat = FingerprintManagerCompat.from(context);

        fingerprintManagerCompat.authenticate(cryptoObject, 0, new CancellationSignal(),
                new FingerprintManagerCompat.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errMsgId, CharSequence errString) {
                        super.onAuthenticationError(errMsgId, errString);
                        updateStatus(String.valueOf(errString));
                        biometricCallback.onAuthenticationError(errMsgId, errString);
                    }

                    @Override
                    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
                        super.onAuthenticationHelp(helpMsgId, helpString);
                        updateStatus(String.valueOf(helpString));
                        biometricCallback.onAuthenticationHelp(helpMsgId, helpString);
                    }

                    @Override
                    public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        dismissDialog();
                        biometricCallback.onAuthenticationSuccessful(result);
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                        updateStatus(context.getString(R.string.biometric_failed));
                        biometricCallback.onAuthenticationFailed();
                    }
                }, null);

        displayBiometricDialog(biometricCallback);

    }

    private void displayBiometricDialog(final BiometricCallback biometricCallback) {
        biometricDialogV23 = new BiometricDialogV23(context, biometricCallback);
        biometricDialogV23.setTitle(title);
        biometricDialogV23.setSubtitle(subtitle);
        biometricDialogV23.setDescription(description);
        biometricDialogV23.setButtonText(negativeButtonText);
        biometricDialogV23.show();
    }

    private void dismissDialog() {
        if(biometricDialogV23 != null) {
            biometricDialogV23.dismiss();
        }
    }

    private void updateStatus(String status) {
        if(biometricDialogV23 != null) {
            biometricDialogV23.updateStatus(status);
        }
    }
}
