package com.configs;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.Getter;

@Getter
@Component
public class ApplicationConfig {

    @Value("${server.port}")
    private String port;

    @Value("${project.version}")
    private String projectVersion;

    @Value("${project.basedir}")
    private String baseDir;

    @Value("${project.name}")
    private String projectName;

    @Value("${project.description}")
    private String description;

}
