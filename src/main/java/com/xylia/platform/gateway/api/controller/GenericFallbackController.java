package com.xylia.platform.gateway.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/fallback")
public class GenericFallbackController {

    @GetMapping("/generic")
    public ResponseEntity<List> fallback() {
        return ResponseEntity.ok(Arrays.asList());

    }
}
