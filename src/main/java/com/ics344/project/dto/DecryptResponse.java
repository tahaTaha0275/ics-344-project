package com.ics344.project.dto;


public class DecryptResponse {
    private String status;    // "OK" or "ERROR"
    private String code;      // e.g., "SIGNATURE_INVALID", "UNWRAP_FAIL", "INTEGRITY_FAIL", "MISSING_KEY"
    private String message;   // human friendly
    private String plaintext; // present when status == "OK"

    public DecryptResponse() {}

    public static DecryptResponse ok(String plaintext) {
        DecryptResponse r = new DecryptResponse();
        r.status = "OK";
        r.code = "OK";
        r.plaintext = plaintext;
        r.message = "Decryption and verification successful";
        return r;
    }

    public static DecryptResponse error(String code, String message) {
        DecryptResponse r = new DecryptResponse();
        r.status = "ERROR";
        r.code = code;
        r.message = message;
        return r;
    }

    // getters / setters
    public String getStatus(){ return status; }
    public void setStatus(String s){ this.status = s; }
    public String getCode(){ return code; }
    public void setCode(String c){ this.code = c; }
    public String getMessage(){ return message; }
    public void setMessage(String m){ this.message = m; }
    public String getPlaintext(){ return plaintext; }
    public void setPlaintext(String p){ this.plaintext = p; }
}
