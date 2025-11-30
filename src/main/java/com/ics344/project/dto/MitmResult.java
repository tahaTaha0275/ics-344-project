package com.ics344.project.dto;

public class MitmResult {
    public boolean success;          // true if the attack was detected / blocked
    public String message;           // human-readable explanation

    public String realSenderId;      // e.g., "alice"
    public String receiverId;        // e.g., "bob"
    public String attackerId;        // e.g., "mallory"

    public String forgedSenderId;    // the ID attacker pretended to be (usually same as realSenderId)

    public String decryptStatus;     // e.g., "SIGNATURE_INVALID"
    public String decryptMessage;    // detailed reason from DecryptResponse

    public String plaintextTried;    // message attacker tried to send
}
