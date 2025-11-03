package com.ics344.project.handler;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String,String>> handleIllegalState(IllegalStateException ex) {
        String msg = ex.getMessage();
        if ("USER_BLOCKED".equals(msg) || "USER_BLOCKED_AFTER_DETECTION".equals(msg)) {
            return ResponseEntity.status(429).body(Map.of(
                    "error", "user_blocked",
                    "message", "Your client is temporarily blocked due to suspicious activity"
            ));
        }
        return ResponseEntity.badRequest().body(Map.of("error", "bad_request", "message", msg));
    }
}
