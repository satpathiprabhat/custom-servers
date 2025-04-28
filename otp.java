package com.example.otp.service;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class OtpService {

    private final TimeBasedOneTimePasswordGenerator totp;
    private final Duration otpPeriod = Duration.ofSeconds(30);
    private final Map<String, SecretKey> userSecrets = new ConcurrentHashMap<>();

    public OtpService() throws NoSuchAlgorithmException {
        this.totp = new TimeBasedOneTimePasswordGenerator(otpPeriod);
    }

    public String generateOtp(String userId) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKey secret = userSecrets.computeIfAbsent(userId, key -> {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance(totp.getAlgorithm());
                keyGen.init(160);
                return keyGen.generateKey();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        });

        String otp = String.format("%06d", totp.generateOneTimePassword(secret, Instant.now()));
        return otp;
    }

    public boolean validateOtp(String userId, String providedOtp) throws InvalidKeyException {
        SecretKey secret = userSecrets.get(userId);
        if (secret == null) return false;

        String currentOtp = String.format("%06d", totp.generateOneTimePassword(secret, Instant.now()));
        return currentOtp.equals(providedOtp);
    }

    public String getSecretBase32(String userId) {
        SecretKey secret = userSecrets.get(userId);
        return secret != null ? Base64.getEncoder().encodeToString(secret.getEncoded()) : null;
    }
}