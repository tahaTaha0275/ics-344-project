package com.ics344.project.controllers;


import com.ics344.project.services.AttackDetector;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/admin/attack")
@RequiredArgsConstructor
public class AttackAdminController {

    private final AttackDetector detector;

    @GetMapping("/blocked")
    public ResponseEntity<Map<String, Long>> getBlocked() {
        return ResponseEntity.ok(detector.getBlockedUsers());
    }

    @PostMapping("/unblock/{userId}")
    public ResponseEntity<?> unblock(@PathVariable String userId) {
        detector.unblock(userId);
        return ResponseEntity.ok(Map.of("status", "OK"));
    }
}
