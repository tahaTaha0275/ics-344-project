package com.ics344.project.controllers;


import com.ics344.project.dto.ImportKeyRequest;
import com.ics344.project.dto.KeyGenerateRequest;
import com.ics344.project.dto.KeyGenerateResponse;
import com.ics344.project.services.KeyService;
import com.ics344.project.dto.PublicKeyResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/keys")
public class KeysController {
    private final KeyService keyService;
    public KeysController(KeyService keyService){ this.keyService = keyService; }

    @PostMapping("/generate")
    public ResponseEntity<KeyGenerateResponse> generate(@RequestBody KeyGenerateRequest req) throws Exception {
        if (req.getUserId() == null || req.getKeySize() == null) {
            return ResponseEntity.badRequest().build();
        }
        Map<String,String> map = keyService.generateKeyPairForUser(req.getUserId(), req.getKeySize());
        KeyGenerateResponse res = new KeyGenerateResponse();
        res.setUserId(map.get("userId"));
        res.setPublicKeyPem(map.get("publicKeyPem"));
        res.setCreatedAt(map.get("createdAt"));
        return ResponseEntity.ok(res);
    }

    @PostMapping("/import")
    public ResponseEntity<Map<String,String>> importPub(@RequestBody ImportKeyRequest req) throws Exception {
        if (req.getUserId() == null || req.getPublicKeyPem() == null) {
            return ResponseEntity.badRequest().build();
        }
        keyService.importPublicKey(req.getUserId(), req.getPublicKeyPem());
        return ResponseEntity.ok(Map.of("status","OK"));
    }

    @GetMapping("/{userId}/public")
    public ResponseEntity<PublicKeyResponse> getPublic(@PathVariable String userId) throws Exception {
        String pem = keyService.getPublicKeyPem(userId);
        return ResponseEntity.ok(new PublicKeyResponse(userId, pem));
    }
}
