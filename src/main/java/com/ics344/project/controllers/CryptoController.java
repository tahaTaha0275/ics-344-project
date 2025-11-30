package com.ics344.project.controllers;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ics344.project.dto.BruteForceResult;
import com.ics344.project.dto.DecryptRequest;
import com.ics344.project.dto.DecryptResponse;
import com.ics344.project.dto.EncryptRequest;
import com.ics344.project.dto.EnvelopeDTO;
import com.ics344.project.dto.MitmResult;
import com.ics344.project.services.CryptoService;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {

    private final CryptoService cryptoService;
    public CryptoController(CryptoService cryptoService) { this.cryptoService = cryptoService; }

    @PostMapping("/encrypt")
    public ResponseEntity<EnvelopeDTO> encrypt(@RequestBody EncryptRequest req) throws Exception {
        if (req.getPlaintext() == null || req.getSenderId() == null || req.getReceiverId() == null) {
            return ResponseEntity.badRequest().build();
        }
        EnvelopeDTO env = cryptoService.encryptEnvelope(
                req.getPlaintext(), req.getSenderId(), req.getReceiverId()
        );
        return ResponseEntity.ok(env);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(@RequestBody DecryptRequest req) {
        if (req == null || req.getEnvelope() == null) {
            return ResponseEntity.badRequest().body(DecryptResponse.error("BAD_INPUT", "Missing envelope in request"));
        }
        DecryptResponse resp = cryptoService.decryptEnvelope(req.getEnvelope());
        return ResponseEntity.ok(resp);
    }

    //Hussain Cipther 
    @PostMapping("/simulate-tamper")
    public DecryptResponse simulateTamper(@RequestBody EnvelopeDTO envelope) {
    EnvelopeDTO tampered = cryptoService.tamperEnvelope(envelope);
    return cryptoService.decryptEnvelope(tampered);
}

//Brute Force
    @PostMapping("/bruteforce-demo")
    public BruteForceResult bruteForceDemo() throws Exception {
        return cryptoService.bruteForceDemo();
    }

    @PostMapping("/bruteforce")
public ResponseEntity<BruteForceResult> bruteForce() throws Exception {
    BruteForceResult result = cryptoService.bruteForceDemo();
    return ResponseEntity.ok(result);
}


//MITM

@PostMapping("/mitm")
public ResponseEntity<MitmResult> mitmAttack(
        @RequestParam String realSenderId,
        @RequestParam String receiverId,
        @RequestParam String attackerId
) {
    MitmResult result = cryptoService.mitmImpersonationDemo(realSenderId, receiverId, attackerId);
    return ResponseEntity.ok(result);
}


    
}
