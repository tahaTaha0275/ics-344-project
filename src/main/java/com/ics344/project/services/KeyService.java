package com.ics344.project.services;


import com.ics344.project.utils.PemUtils;
import org.springframework.stereotype.Service;

import java.io.File;
import java.security.*;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
public class KeyService {
    private final File storageDir = new File("keys"); // relative to app working dir

    public KeyService() {
        if (!storageDir.exists()) storageDir.mkdirs();
    }

    public Map<String, String> generateKeyPairForUser(String userId, int keySize) throws GeneralSecurityException, java.io.IOException {
        if (keySize != 2048 && keySize != 3072) {
            throw new IllegalArgumentException("Allowed key sizes: 2048 or 3072");
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        KeyPair kp = kpg.generateKeyPair();

        String pubPem = PemUtils.toPemPublicKey(kp.getPublic());
        String privPem = PemUtils.toPemPrivateKey(kp.getPrivate());

        File privFile = new File(storageDir, userId + "_private.pem");
        File pubFile  = new File(storageDir, userId + "_public.pem");

        PemUtils.writeStringToFile(privFile, privPem);
        PemUtils.writeStringToFile(pubFile, pubPem);

        Map<String,String> out = new HashMap<>();
        out.put("userId", userId);
        out.put("publicKeyPem", pubPem);
        out.put("createdAt", Instant.now().toString());
        return out;
    }

    public void importPublicKey(String userId, String publicKeyPem) throws java.io.IOException {
        File pubFile  = new File(storageDir, userId + "_public.pem");
        PemUtils.writeStringToFile(pubFile, publicKeyPem);
    }

    public String getPublicKeyPem(String userId) throws java.io.IOException {
        File pubFile = new File(storageDir, userId + "_public.pem");
        if (!pubFile.exists()) throw new java.io.FileNotFoundException("Public key not found for user: " + userId);
        return PemUtils.readStringFromFile(pubFile);
    }
}
