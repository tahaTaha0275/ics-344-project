package com.ics344.project.services;


import com.ics344.project.dto.ChatMessage;
import com.ics344.project.dto.EnvelopeDTO;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ChatService {
    private final Map<String, SseEmitter> emitters = new ConcurrentHashMap<>();
    private final CryptoService cryptoService;

    public ChatService(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    public SseEmitter connect(String userId) {
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        emitters.put(userId, emitter);

        emitter.onCompletion(() -> emitters.remove(userId));
        emitter.onTimeout(() -> emitters.remove(userId));
        emitter.onError(e -> emitters.remove(userId));

        return emitter;
    }

    public void sendMessage(String message, String senderId, String receiverId) throws Exception {
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
                emitters.remove(receiverId);
                throw e;
            }
        }
    }
}