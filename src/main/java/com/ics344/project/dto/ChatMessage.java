package com.ics344.project.dto;


public class ChatMessage {
    private String senderId;
    private String receiverId;
    private EnvelopeDTO envelope;
    private String timestamp;

    // Getters and setters
    public String getSenderId() { return senderId; }
    public void setSenderId(String senderId) { this.senderId = senderId; }
    public String getReceiverId() { return receiverId; }
    public void setReceiverId(String receiverId) { this.receiverId = receiverId; }
    public EnvelopeDTO getEnvelope() { return envelope; }
    public void setEnvelope(EnvelopeDTO envelope) { this.envelope = envelope; }
    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
}