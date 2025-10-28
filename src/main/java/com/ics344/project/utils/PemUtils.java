package com.ics344.project.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public final class PemUtils {
    private PemUtils() {}

    public static String toPemPublicKey(PublicKey publicKey) {
        String b64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + chunk(b64) + "\n-----END PUBLIC KEY-----";
    }

    public static String toPemPrivateKey(PrivateKey privateKey) {
        String b64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + chunk(b64) + "\n-----END PRIVATE KEY-----";
    }

    private static String chunk(String s) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < s.length()) {
            int end = Math.min(i + 64, s.length());
            sb.append(s, i, end).append('\n');
            i = end;
        }
        return sb.toString().trim();
    }

    public static PublicKey publicKeyFromPem(String pem) throws GeneralSecurityException {
        String base64 = pem.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s","");

        byte[] bytes = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey privateKeyFromPem(String pem) throws GeneralSecurityException {
        String base64 = pem.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s","");
        byte[] bytes = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // simple file write
    public static void writeStringToFile(File file, String content) throws IOException {
        file.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
            fos.flush();
        }
        // set restrictive permissions if possible (best-effort)
        file.setReadable(true, true);
        file.setWritable(true, true);
    }

    public static String readStringFromFile(File file) throws IOException {
        return new String(java.nio.file.Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
    }
}
