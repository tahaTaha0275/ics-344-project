package com.ics344.project.controllers;


import com.ics344.project.services.ChatService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@RequestMapping("/api/chat")
public class ChatController {
    private final ChatService chatService;

    public ChatController(ChatService chatService) {
        this.chatService = chatService;
    }

    @GetMapping(path = "/connect/{userId}", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter connect(@PathVariable String userId) {
        return chatService.connect(userId);
    }

    @PostMapping("/send")
    public void sendMessage(
            @RequestParam String message,
            @RequestParam String senderId,
            @RequestParam String receiverId) throws Exception {
        chatService.sendMessage(message, senderId, receiverId);
    }
}