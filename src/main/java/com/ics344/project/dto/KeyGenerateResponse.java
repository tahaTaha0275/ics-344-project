package com.ics344.project.dto;


public class KeyGenerateResponse {
    private String userId;
    private String publicKeyPem;
    private String createdAt;

    // getters/setters
    public String getUserId(){return userId;}
    public void setUserId(String u){this.userId=u;}
    public String getPublicKeyPem(){return publicKeyPem;}
    public void setPublicKeyPem(String p){this.publicKeyPem=p;}
    public String getCreatedAt(){return createdAt;}
    public void setCreatedAt(String c){this.createdAt=c;}
}
