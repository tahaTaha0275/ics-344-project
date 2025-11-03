package com.ics344.project.services;


import com.ics344.project.dto.ChatMessage;
import com.ics344.project.dto.EnvelopeDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class ChatService {

    private final Map<String, SseEmitter> emitters = new ConcurrentHashMap<>();
    private final CryptoService cryptoService;
    private final AttackDetector attackDetector;

    public ChatService(CryptoService cryptoService, AttackDetector attackDetector) {
        this.cryptoService = cryptoService;
        this.attackDetector = attackDetector;
    }

    public SseEmitter connect(String userId) {
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        emitters.put(userId, emitter);

        emitter.onCompletion(() -> emitters.remove(userId));
        emitter.onTimeout(() -> emitters.remove(userId));
        emitter.onError(e -> emitters.remove(userId));

        log.info("SSE connected for user {}", userId);
        return emitter;
    }

    /**
     * sendMessage - checks attack detector before proceeding; if attacker detected:
     *  - logs an attack event,
     *  - disconnects the attacker's SSE emitter,
     *  - throws IllegalStateException with a specific message (mapped by GlobalExceptionHandler).
     *
     * When not blocked, behavior is identical to previous implementation:
     *  - build EnvelopeDTO via cryptoService.encryptEnvelope(...)
     *  - send ChatMessage event to receiver's SSE emitter (if present)
     */
    public void sendMessage(String message, String senderId, String receiverId) throws Exception {
        // 0) If blocked already, reject early
        if (attackDetector.isBlocked(senderId)) {
            throw new IllegalStateException("USER_BLOCKED");
        }

        // 1) Record request and detect threshold violations
        boolean triggered = attackDetector.recordRequestAndCheckBlock(senderId);
        if (triggered) {
            log.warn("DoS detected from user '{}'. Blocking for configured duration and disconnecting emitter.", senderId);
            logAttackEvent(senderId, "RATE_LIMIT_EXCEEDED");
            disconnectUser(senderId);
            throw new IllegalStateException("USER_BLOCKED_AFTER_DETECTION");
        }

        // 2) Normal flow: encrypt and send (unchanged)
        EnvelopeDTO envelope = cryptoService.encryptEnvelope(message, senderId, receiverId);

        ChatMessage chatMessage = new ChatMessage();
        chatMessage.setSenderId(senderId);
        chatMessage.setReceiverId(receiverId);
        chatMessage.setEnvelope(envelope);
        chatMessage.setTimestamp(envelope.timestamp);

        SseEmitter emitter = emitters.get(receiverId);
        if (emitter != null) {
            try {
                emitter.send(SseEmitter.event()
                        .name("message")
                        .data(chatMessage));
            } catch (Exception e) {
                // remove emitter on failure (same behavior as before)
                emitters.remove(receiverId);
                throw e;
            }
        }
    }

    private void disconnectUser(String userId) {
        SseEmitter em = emitters.remove(userId);
        if (em != null) {
            try {
                em.complete();
                log.info("Disconnected SSE emitter for user {}", userId);
            } catch (Exception e) {
                log.warn("Error closing emitter for user {}: {}", userId, e.getMessage());
            }
        } else {
            log.debug("No emitter found for user {} to disconnect", userId);
        }
    }

    private void logAttackEvent(String userId, String reason) {
        // structured log entry for forensic purposes
        log.error("ATTACK_DETECTED user={} reason={} time={}", userId, reason, java.time.Instant.now().toString());
        // optionally: append to dedicated file or forward to monitoring
    }

    // admin/testing helper
    public boolean disconnectIfConnected(String userId) {
        SseEmitter em = emitters.remove(userId);
        if (em != null) {
            try { em.complete(); } catch (Exception ignored) {}
            return true;
        }
        return false;
    }
}
