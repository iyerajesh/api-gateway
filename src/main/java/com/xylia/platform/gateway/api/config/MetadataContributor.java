package com.xylia.platform.gateway.api.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class MetadataContributor implements InfoContributor {

    public static final String PATTERN = "yyyy-MM-dd'T'HH:mm:ss:SSS'Z'";

    @Autowired
    private ApplicationContext applicationContext;

    @Override
    public void contribute(Info.Builder builder) {

        Map<String, Object> details = new HashMap<>();
        DateFormat simple = new SimpleDateFormat(PATTERN);

        details.put("startup-date", simple.format(new Date(applicationContext.getStartupDate())));

        builder.withDetail("context", details);
    }
}
