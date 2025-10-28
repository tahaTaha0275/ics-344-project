package com.ics344.project.dto;


public class ImportKeyRequest {
    private String userId;
    private String publicKeyPem;
    // getters/setters
    public String getUserId(){return userId;}
    public void setUserId(String u){this.userId=u;}
    public String getPublicKeyPem(){return publicKeyPem;}
    public void setPublicKeyPem(String p){this.publicKeyPem=p;}
}
