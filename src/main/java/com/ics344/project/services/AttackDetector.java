package com.ics344.project.services;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple sliding-window rate detector & in-memory blocklist.
 * Tunable parameters: WINDOW_SECONDS, MAX_REQUESTS, BAN_SECONDS
 *
 * NOTE: in-memory only. For multi-instance deployments use Redis or similar.
 */
@Service
public class AttackDetector {

    // TUNE these for your experiments
    private final int WINDOW_SECONDS = 10;   // sliding window length in seconds
    private final int MAX_REQUESTS = 20;     // max requests allowed from single user in window
    private final int BAN_SECONDS = 300;     // ban duration when threshold exceeded (seconds)

    // map senderId -> deque of epoch seconds (request timestamps)
    private final Map<String, Deque<Long>> recentRequests = new ConcurrentHashMap<>();

    // map senderId -> ban expiry epoch seconds
    private final Map<String, Long> blockedUntil = new ConcurrentHashMap<>();

    /**
     * Record a request for senderId. Returns true if this request triggered a block.
     * If the user is already blocked this returns false (caller should check isBlocked first).
     */
    public synchronized boolean recordRequestAndCheckBlock(String senderId) {
        long now = Instant.now().getEpochSecond();

        // expire previous block if passed
        Long until = blockedUntil.get(senderId);
        if (until != null && now >= until) {
            blockedUntil.remove(senderId);
        }

        // if currently blocked, do nothing (caller should treat as blocked)
        if (isBlocked(senderId)) {
            return false;
        }

        Deque<Long> dq = recentRequests.computeIfAbsent(senderId, k -> new ArrayDeque<>());
        // discard old timestamps outside the window
        while (!dq.isEmpty() && dq.peekFirst() <= now - WINDOW_SECONDS) {
            dq.pollFirst();
        }
        dq.addLast(now);

        if (dq.size() > MAX_REQUESTS) {
            // trigger ban
            blockedUntil.put(senderId, now + BAN_SECONDS);
            // clear recent requests
            recentRequests.remove(senderId);
            return true;
        }
        return false;
    }

    public synchronized boolean isBlocked(String senderId) {
        Long until = blockedUntil.get(senderId);
        long now = Instant.now().getEpochSecond();
        if (until == null) return false;
        if (now >= until) {
            blockedUntil.remove(senderId);
            return false;
        }
        return true;
    }


    // admin helpers
    public Map<String, Long> getBlockedUsers() {
        return Collections.unmodifiableMap(blockedUntil);
    }

    public void unblock(String senderId) {
        blockedUntil.remove(senderId);
    }
}
