package com.ics344.project.controllers;


import com.ics344.project.dto.DecryptRequest;
import com.ics344.project.dto.DecryptResponse;
import com.ics344.project.dto.EncryptRequest;
import com.ics344.project.dto.EnvelopeDTO;
import com.ics344.project.services.CryptoService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
}
