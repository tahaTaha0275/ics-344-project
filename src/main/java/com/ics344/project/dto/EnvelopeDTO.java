package com.ics344.project.dto;


/** All binary fields are Base64-encoded strings. */
public class EnvelopeDTO {
    public String senderId;
    public String receiverId;
    public String sessionKeyEnc; // RSA-OAEP(SHA-256) of AES key (Base64)
    public String iv;            // 12 bytes (Base64)
    public String ciphertext;    // AES-GCM ciphertext (Base64, WITHOUT tag)
    public String tag;           // 16 bytes (Base64)
    public String signature;     // RSA-SHA256 signature over canonical bytes (Base64)
    public String timestamp;     // ISO-8601
    public String nonce;         // random 16 bytes (Base64)
}
