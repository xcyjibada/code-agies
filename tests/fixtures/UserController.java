package com.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * A sample Spring Boot controller with taint-sink patterns.
 */
class UserController {

    private String name;

    @GetMapping
    public String getUser(String id) {
        String query = "SELECT * FROM users WHERE id = " + id;
        Runtime.getRuntime().exec(query);
        return query;
    }

    @PostMapping
    public String createUser(@RequestParam String input) {
        String cmd = "echo " + input;
        Runtime runtime = Runtime.getRuntime();
        runtime.exec(cmd);
        return cmd;
    }

    @GetMapping
    public String getProfile(String userId) {
        // Safe — no sink with tainted data
        String safe = "hello";
        return safe;
    }

    public String notAHandler(String safe) {
        // Not a handler — no annotation, so params not seeded as sources
        String cmd = "ls " + safe;
        Runtime.getRuntime().exec(cmd);
        return cmd;
    }
}
