package com.ics344.project.services;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import com.ics344.project.dto.BruteForceResult;
import com.ics344.project.dto.DecryptResponse;
import com.ics344.project.dto.EnvelopeDTO;
import com.ics344.project.dto.MitmResult;
import com.ics344.project.utils.PemUtils;

@Service
public class CryptoService {

    //Addition from Hussain
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CryptoService.class);

    //

    /** Builds a full, signed envelope per Milestone B rules. */
    public EnvelopeDTO encryptEnvelope(String plaintext, String senderId, String receiverId) throws Exception {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(senderId, "senderId");
        Objects.requireNonNull(receiverId, "receiverId");

        // 1) Load keys
        PrivateKey senderPriv = PemUtils.privateKeyFromPem(
                PemUtils.readStringFromFile(new File("keys", senderId + "_private.pem"))
        );
        PublicKey receiverPub = PemUtils.publicKeyFromPem(
                PemUtils.readStringFromFile(new File("keys", receiverId + "_public.pem"))
        );

        // 2) Generate AES-256 session key + 12-byte IV
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        byte[] iv = new byte[12];
        SecureRandom sr = SecureRandom.getInstanceStrong();
        sr.nextBytes(iv);

        // 3) Encrypt with AES/GCM/NoPadding
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm = new GCMParameterSpec(128, iv);
        aes.init(Cipher.ENCRYPT_MODE, aesKey, gcm);
        byte[] ctWithTag = aes.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Split ciphertext and tag (last 16 bytes is tag)
        int tagLen = 16;
        int ctLen = ctWithTag.length - tagLen;
        byte[] ciphertext = new byte[ctLen];
        byte[] tag = new byte[tagLen];
        System.arraycopy(ctWithTag, 0, ciphertext, 0, ctLen);
        System.arraycopy(ctWithTag, ctLen, tag, 0, tagLen);

        // 4) Wrap session key with RSA-OAEP(SHA-256)
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
        );
        rsa.init(Cipher.ENCRYPT_MODE, receiverPub, oaep);
        byte[] sessionKeyEnc = rsa.doFinal(aesKey.getEncoded());

        // 5) Fill envelope meta
        EnvelopeDTO env = new EnvelopeDTO();
        env.senderId   = senderId;
        env.receiverId = receiverId;
        env.sessionKeyEnc = b64(sessionKeyEnc);
        env.iv         = b64(iv);
        env.ciphertext = b64(ciphertext);
        env.tag        = b64(tag);
        env.timestamp  = Instant.now().toString();

        byte[] nonce = new byte[16];
        sr.nextBytes(nonce);
        env.nonce = b64(nonce);

        // 6) Sign RSA-SHA256 over canonical bytes (fixed order)
        byte[] canon = canonicalBytes(env);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(senderPriv);
        sig.update(canon);
        env.signature = b64(sig.sign());

        return env;
    }

    /** Decrypts & verifies an envelope; returns explicit codes on failure. */
    public DecryptResponse decryptEnvelope(EnvelopeDTO env) {
        try {
            if (env == null) return DecryptResponse.error("BAD_INPUT", "No envelope provided");

            String senderId = env.senderId;
            String receiverId = env.receiverId;
            if (senderId == null || receiverId == null || env.sessionKeyEnc == null
                    || env.iv == null || env.ciphertext == null || env.tag == null || env.signature == null) {
                return DecryptResponse.error("BAD_INPUT", "Envelope missing required fields");
            }

            // 0) Load keys
            File senderPubFile = new File("keys", senderId + "_public.pem");
            File receiverPrivFile = new File("keys", receiverId + "_private.pem");
            if (!senderPubFile.exists() || !receiverPrivFile.exists()) {
                return DecryptResponse.error("MISSING_KEY",
                        "Missing keys. Need keys/" + senderId + "_public.pem and keys/" + receiverId + "_private.pem");
            }

            PublicKey senderPub = PemUtils.publicKeyFromPem(PemUtils.readStringFromFile(senderPubFile));
            PrivateKey receiverPriv = PemUtils.privateKeyFromPem(PemUtils.readStringFromFile(receiverPrivFile));

            // 1) Verify signature (SHA256withRSA) over canonical bytes
            byte[] canon = canonicalBytes(env);
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(senderPub);
            verifier.update(canon);
            boolean sigOk;
            try {
                sigOk = verifier.verify(Base64.getDecoder().decode(env.signature));
            } catch (IllegalArgumentException e) {
                return DecryptResponse.error("BAD_INPUT", "Signature field is not valid base64");
            }
            if (!sigOk) {
                return DecryptResponse.error("SIGNATURE_INVALID", "Signature verification failed");
            }

            // 2) Unwrap session AES key using RSA-OAEP(SHA-256)
            byte[] sessionEncBytes;
            try {
                sessionEncBytes = Base64.getDecoder().decode(env.sessionKeyEnc);
            } catch (IllegalArgumentException e) {
                return DecryptResponse.error("BAD_INPUT", "sessionKeyEnc not valid base64");
            }

            byte[] aesKeyBytes;
            try {
                Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                OAEPParameterSpec oaep = new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
                );
                rsa.init(Cipher.DECRYPT_MODE, receiverPriv, oaep);
                aesKeyBytes = rsa.doFinal(sessionEncBytes);
            } catch (Exception e) {
                return DecryptResponse.error("UNWRAP_FAIL", "Failed to unwrap AES session key: " + e.getMessage());
            }

            // 3) AES-GCM decrypt
            byte[] iv, ciphertext, tag;
            try {
                iv = Base64.getDecoder().decode(env.iv);
                ciphertext = Base64.getDecoder().decode(env.ciphertext);
                tag = Base64.getDecoder().decode(env.tag);
            } catch (IllegalArgumentException e) {
                return DecryptResponse.error("BAD_INPUT", "iv/ciphertext/tag not valid base64");
            }

            // Reconstruct ct||tag for Cipher.doFinal
            byte[] ctWithTag = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, ctWithTag, 0, ciphertext.length);
            System.arraycopy(tag, 0, ctWithTag, ciphertext.length, tag.length);

            try {
                SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
                Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcm = new GCMParameterSpec(128, iv);
                aes.init(Cipher.DECRYPT_MODE, aesKey, gcm);
                byte[] plain = aes.doFinal(ctWithTag);
                String plaintext = new String(plain, StandardCharsets.UTF_8);
                return DecryptResponse.ok(plaintext);
            } catch (javax.crypto.AEADBadTagException ex) {
                return DecryptResponse.error("INTEGRITY_FAIL", "AES-GCM authentication failed (bad tag)");
            } catch (Exception ex) {
                return DecryptResponse.error("ERROR", "AES decryption error: " + ex.getMessage());
            }

        } catch (Exception e) {
            return DecryptResponse.error("ERROR", "Unexpected error: " + e.getMessage());
        }
    }

    /** Canonical byte order for signing/verifying (unchanged across encrypt/decrypt). */
    public static byte[] canonicalBytes(EnvelopeDTO e) {
        String joined =
                nz(e.senderId) + "\n" +
                        nz(e.receiverId) + "\n" +
                        nz(e.sessionKeyEnc) + "\n" +
                        nz(e.iv) + "\n" +
                        nz(e.ciphertext) + "\n" +
                        nz(e.tag) + "\n" +
                        nz(e.timestamp) + "\n" +
                        nz(e.nonce);
        return joined.getBytes(StandardCharsets.UTF_8);
    }

    private static String b64(byte[] x) { return Base64.getEncoder().encodeToString(x); }
    private static String nz(String s) { return s == null ? "" : s; }
    
    
    // Hussain Work
    
    //Ciphertext Tampering 
    
    public EnvelopeDTO tamperEnvelope(EnvelopeDTO original) {
        if (original == null) return null;
        
        EnvelopeDTO tampered = new EnvelopeDTO();
        tampered.senderId     = original.senderId;
        tampered.receiverId   = original.receiverId;
        tampered.sessionKeyEnc= original.sessionKeyEnc;
        tampered.iv           = original.iv;
        tampered.tag          = original.tag;
        tampered.timestamp    = original.timestamp;
        tampered.nonce        = original.nonce;
        tampered.signature    = original.signature; // attacker cannot re-sign
    
    try {
        byte[] ctBytes = Base64.getDecoder().decode(original.ciphertext);
        if (ctBytes.length > 0) {
            ctBytes[0] ^= 0x01; // flip 1 bit
        }
        tampered.ciphertext = Base64.getEncoder().encodeToString(ctBytes);
    } catch (IllegalArgumentException e) {
        // if ciphertext is not valid base64, just keep original
        tampered.ciphertext = original.ciphertext;
    }
    
    return tampered;
}

//Brute Force
 // on a WEAK 4-digit PIN 

    /** Derive a very weak AES-256 key from a 4-digit PIN (for demo ONLY). */
    private static SecretKeySpec weakKeyFromPin(String pin) {
        byte[] pinBytes = pin.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = new byte[32]; // AES-256, but only first few bytes are from PIN
        System.arraycopy(pinBytes, 0, keyBytes, 0, Math.min(pinBytes.length, keyBytes.length));
        return new SecretKeySpec(keyBytes, "AES");
    }

    /** Runs a full brute-force demo on a 4-digit PIN key. */
    public BruteForceResult bruteForceDemo() throws Exception {
        String plaintext = "Hello ICS344, this is a secret demo message.";

        SecureRandom sr = SecureRandom.getInstanceStrong();

        // 1) Pick a random 4-digit PIN and derive a weak AES key
        int pinInt = sr.nextInt(10000); // 0..9999
        String actualPin = String.format("%04d", pinInt);
        SecretKeySpec weakKey = weakKeyFromPin(actualPin);

        // 2) Encrypt with AES-GCM using this weak key
        byte[] iv = new byte[12];
        sr.nextBytes(iv);

        Cipher aesEnc = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmEnc = new GCMParameterSpec(128, iv);
        aesEnc.init(Cipher.ENCRYPT_MODE, weakKey, gcmEnc);
        byte[] ctWithTag = aesEnc.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        String ctB64 = Base64.getEncoder().encodeToString(ctWithTag);
        String ivB64 = Base64.getEncoder().encodeToString(iv);

        // 3) Attacker brute-forces all 0000..9999
        byte[] ctBytes = ctWithTag; // no need to decode each time
        String recoveredPlaintext = null;
        String recoveredPin = null;
        int attempts = 0;

        long start = System.nanoTime();

        for (int i = 0; i < 10000; i++) {
            String candidatePin = String.format("%04d", i);
            SecretKeySpec trialKey = weakKeyFromPin(candidatePin);
            attempts++;

            try {
                Cipher aesDec = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmDec = new GCMParameterSpec(128, iv);
                aesDec.init(Cipher.DECRYPT_MODE, trialKey, gcmDec);
                byte[] ptBytes = aesDec.doFinal(ctBytes);
                String pt = new String(ptBytes, StandardCharsets.UTF_8);

                // Attacker assumes they know that message starts with "Hello ICS344"
                if (pt.startsWith("Hello ICS344")) {
                    recoveredPlaintext = pt;
                    recoveredPin = candidatePin;
                    break;
                }
            } catch (Exception ignored) {
                // wrong key -> decryption fails; attacker just tries next one
            }
        }

        long end = System.nanoTime();
        long millis = (end - start) / 1_000_000L;

        BruteForceResult result = new BruteForceResult();
        result.ciphertext = ctB64;
        result.iv = ivB64;
        result.actualPin = actualPin;
        result.recoveredPin = recoveredPin;
        result.recoveredPlaintext = recoveredPlaintext;
        result.attempts = attempts;
        result.millis = millis;

        if (recoveredPin != null) {
            result.success = true;
            result.message = "Brute force succeeded on a weak 4-digit PIN key.";
        } else {
            result.success = false;
            result.message = "Brute force failed within 0000-9999 key space (unexpected).";
        }

        log.info("Brute-force demo: actualPin={}, recoveredPin={}, attempts={}, millis={}",
                actualPin, recoveredPin, attempts, millis);

        return result;
    }



    //MINTM

    private EnvelopeDTO forgeEnvelopeImpersonatingSender(
        String plaintext,
        String forgedSenderId,
        String receiverId,
        String attackerId
) throws Exception {

    Objects.requireNonNull(plaintext);
    Objects.requireNonNull(forgedSenderId);
    Objects.requireNonNull(receiverId);
    Objects.requireNonNull(attackerId);

    // 1) Attacker’s private key (wrong key)
    PrivateKey attackerPriv = PemUtils.privateKeyFromPem(
            PemUtils.readStringFromFile(new File("keys", attackerId + "_private.pem"))
    );

    // 2) Receiver’s real public key
    PublicKey receiverPub = PemUtils.publicKeyFromPem(
            PemUtils.readStringFromFile(new File("keys", receiverId + "_public.pem"))
    );

    // 3) AES key + IV
    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(256);
    SecretKey aesKey = kg.generateKey();

    byte[] iv = new byte[12];
    SecureRandom sr = SecureRandom.getInstanceStrong();
    sr.nextBytes(iv);

    Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcm = new GCMParameterSpec(128, iv);
    aes.init(Cipher.ENCRYPT_MODE, aesKey, gcm);
    byte[] ctWithTag = aes.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

    int tagLen = 16;
    int ctLen = ctWithTag.length - tagLen;
    byte[] ciphertext = new byte[ctLen];
    byte[] tag = new byte[tagLen];
    System.arraycopy(ctWithTag, 0, ciphertext, 0, ctLen);
    System.arraycopy(ctWithTag, ctLen, tag, 0, tagLen);

    // 4) Wrap AES key
    Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    OAEPParameterSpec oaep = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
    );
    rsa.init(Cipher.ENCRYPT_MODE, receiverPub, oaep);
    byte[] sessionKeyEnc = rsa.doFinal(aesKey.getEncoded());

    // 5) Build forged envelope (senderId lies)
    EnvelopeDTO env = new EnvelopeDTO();
    env.senderId      = forgedSenderId; // fake!
    env.receiverId    = receiverId;
    env.sessionKeyEnc = Base64.getEncoder().encodeToString(sessionKeyEnc);
    env.iv            = Base64.getEncoder().encodeToString(iv);
    env.ciphertext    = Base64.getEncoder().encodeToString(ciphertext);
    env.tag           = Base64.getEncoder().encodeToString(tag);
    env.timestamp     = Instant.now().toString();

    byte[] nonce = new byte[16];
    sr.nextBytes(nonce);
    env.nonce = Base64.getEncoder().encodeToString(nonce);

    // 6) Attacker signs – but receiver will verify with realSenderId public key → mismatch
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initSign(attackerPriv);
    sig.update(canonicalBytes(env));
    env.signature = Base64.getEncoder().encodeToString(sig.sign());

    return env;
}


public MitmResult mitmImpersonationDemo(String realSenderId, String receiverId, String attackerId) {
    MitmResult result = new MitmResult();
    result.realSenderId = realSenderId;
    result.receiverId = receiverId;
    result.attackerId = attackerId;
    result.forgedSenderId = realSenderId;

    String plaintext = "Hello ICS344, this is a MITM impersonation demo.";

    try {
        // Attacker forges an envelope pretending to be realSenderId
        EnvelopeDTO forged = forgeEnvelopeImpersonatingSender(
                plaintext,
                realSenderId,  // forged sender ID in envelope metadata
                receiverId,
                attackerId
        );

        // Receiver tries decrypting normally
        DecryptResponse resp = decryptEnvelope(forged);

        result.decryptStatus = resp.getCode() != null ? resp.getCode() : resp.getStatus();
        result.decryptMessage = resp.getMessage();
        result.plaintextTried = plaintext;

        // Detection: signature mismatch
        if (!"OK".equalsIgnoreCase(result.decryptStatus)) {
            result.success = true;
            result.message =
                "MITM impersonation attack was detected. " +
                "Attacker signed with their own private key while claiming to be '" +
                realSenderId + "', causing SIGNATURE_INVALID.";
        } else {
            result.success = false;
            result.message = "Unexpected: forged message was accepted!";
        }

        log.info("MITM demo: realSenderId={}, receiverId={}, attackerId={}, decryptStatus={}",
                realSenderId, receiverId, attackerId, result.decryptStatus);

    } catch (Exception e) {
        result.success = false;
        result.decryptStatus = "ERROR";
        result.decryptMessage = e.getMessage();
        result.message = "Exception during MITM attack demo: " + e.getMessage();
        log.warn("MITM attack demo failed", e);
    }

    return result;
}


}