package com.ics344.project.dto;


public class KeyGenerateRequest {
    private String userId;
    private Integer keySize; // 2048 | 3072

    // getters/setters
    public String getUserId(){return userId;}
    public void setUserId(String u){this.userId=u;}
    public Integer getKeySize(){return keySize;}
    public void setKeySize(Integer k){this.keySize=k;}
}
