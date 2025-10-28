package com.ics344.project.dto;


public class EncryptRequest {
    private String plaintext;
    private String senderId;
    private String receiverId;

    public String getPlaintext() { return plaintext; }
    public void setPlaintext(String plaintext) { this.plaintext = plaintext; }
    public String getSenderId() { return senderId; }
    public void setSenderId(String senderId) { this.senderId = senderId; }
    public String getReceiverId() { return receiverId; }
    public void setReceiverId(String receiverId) { this.receiverId = receiverId; }
}
