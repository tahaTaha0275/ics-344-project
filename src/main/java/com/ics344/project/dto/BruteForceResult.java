package com.ics344.project.dto;

public class BruteForceResult {

    public boolean success;
    public String message;

    public String ciphertext;         // base64 (AES-GCM, weak key)
    public String iv;                 // base64
    public String actualPin;          // the secret 4-digit PIN used
    public String recoveredPin;       // PIN found by brute force
    public String recoveredPlaintext; // plaintext recovered by attacker

    public int attempts;              // how many keys tried
    public long millis;               // how long brute force took in ms
}
