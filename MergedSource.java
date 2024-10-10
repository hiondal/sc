// File: scg/build.gradle
dependencies {
    implementation 'org.springframework.cloud:spring-cloud-starter-gateway'
    implementation 'org.springframework.cloud:spring-cloud-starter-netflix-eureka-client'

    //-- 기본 L/B인 Ribbon대신 Load Balancer사용
    implementation 'org.springframework.cloud:spring-cloud-starter-loadbalancer'
    //-- Load Balancer가 사용할 캐시를 Caffeine으로 변경
    implementation 'com.github.ben-manes.caffeine:caffeine'
    implementation 'org.springframework.boot:spring-boot-starter-cache'

    implementation 'io.jsonwebtoken:jjwt-api:0.12.5'
    implementation 'io.jsonwebtoken:jjwt-impl:0.12.5'
    implementation 'io.jsonwebtoken:jjwt-jackson:0.12.5'

    implementation 'org.springframework.boot:spring-boot-starter-security'
}

bootJar {
    archiveFileName = "scg.jar"
}


// File: scg/build/resources/main/application.yml
server:
  port: ${SERVER_PORT:19080}
spring:
  application:
    name: scg
  jwt:
    secret: ${JWT_SECRET:8O2HQ13etL2BWZvYOiWsJ5uWFoLi6NBUG8divYVoCgtHVvlk3dqRksMl16toztDUeBTSIuOOPvHIrYq11G2BwQ==}
  # -- Load banancer 설정 : 기본 L/B인 Ribbon비활성화
  cloud.loadbalancer:
    ribbon.enabled: false
    cache.enabled: true

  # -- Load Balancer의 캐시 타입 설정
  cache.type: caffeine

# Eureka client 설정
# hostname은 서버를 구별하는 유일한 값이면 됨. instanceId는 Eureka에 등록된느 ID임 (라우팅할 때 주소 아님)
# 라우팅 주소는 아래와 같이 결정됨
# - preferIpAddress: false -> http://hostname:nonSecurePort, https://hostname:securePort
# - preferIpAddress: true  -> http://ip:nonSecurePort, https://ip:securePort
# 연결되는 주소는 https://{eureka ingress host}/eureka/apps/{service id}의 결과에서 homepageUrl값임
# 생존신고를 하는 주기(lease-renewal-interval-in-seconds. 기본 30초)와
# 만료 간주 시간(Eureka서버가 몇 초 동안 생존 신고를 못 받으면 만료로 간주할 지 판단하는 시간. 기본 90초)을 적절히 정의
# preferIpAddress를 false로 하고 hostname에 k8s DNS주소를 설정하는 방식은 StatefulSet으로 배포하는 경우에만 동작함
# (Deployment로 배포한 Pod는 고유 주소가 생기지 않기 때문임)
eureka:
  instance:
    hostname: ${HOSTNAME:localhost}
    instanceId: ${HOSTNAME:localhost}:${SERVER_PORT:19080}
    preferIpAddress: true
    nonSecurePort: ${SERVER_PORT:19080}
    securePort: 443
    nonSecurePortEnabled: true
    securePortEnabled: false
    lease-renewal-interval-in-seconds: 5
    lease-expiration-duration-in-seconds: 10
  client:
    service-url:
      defaultZone: ${EUREKA_SERVERS:http://eureka1.127.0.0.1.nip.io:8761/eureka/,http://eureka2.127.0.0.1.nip.io:8762/eureka/}
    registryFetchIntervalSeconds: 5
    instanceInfoReplicationIntervalSeconds: 5

logging:
  level:
    root: INFO
    org.springframework.cloud.gateway: INFO

# -- Actuator
management:
  endpoints:
    web:
      exposure:
        include: health, info, env, mappings, routes

#========= 라우팅
spring.cloud.gateway:
  # CORS
  globalcors:
    allowedOrigins: ${ALLOWED_ORIGINS:http://localhost:3000}

  # Timeout
  httpclient:
    connect-timeout: 1000
    response-timeout: 3000

  # Routing
  # 모든 서비스가 k8s환경에서만 서비스 된다면 Eureka를 안 쓰고 k8s서비스로 L/B하는게 제일 좋음
  # 왜냐하면 k8s서비스의 liveness/readiness 체크하여 연결하는 기능을 사용할 수 있고, 불필요한 Eureka 네트워킹을 안할 수 있기 때문임
  # 이 예제에서는 Eureka에 Pod IP를 등록하고 SCG가 L/B하고 있음. 로그인요청만 Eureka연동하고, 나머지는 k8s서비스 사용함
  routes:
    - id: helloworld
      uri: lb://helloworld
      predicates:
        - Path=/hey/**
      filters:
        - RewritePath=/hey/(?<uri>.*), /${uri}

    - id: auth
      uri: lb://member-service
      predicates:
        - Path=/api/auth/**

    - id: member
      uri: lb://member-service
      predicates:
        - Path=/api/members/**

    - id: subrecommend
      uri: lb://subrecommend-service
      predicates:
        - Path=/api/subrecommend/**
      filters:
        - RewritePath=/api/subrecommend/(?<segment>.*), /api/${segment}

    - id: mysub
      uri: lb://mysub-service
      predicates:
        - Path=/api/my-subs/**

    - id: mygrp
      uri: lb://mygrp-service
      predicates:
        - Path=/api/my-groups/**

    - id: transfer
      uri: lb://transfer-service
      predicates:
        - Path=/api/transfer/**
      filters:
        - name: Retry
          args:
            retries: 5              # 재시도 횟수
            statuses: BAD_GATEWAY, INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE #재시도 할 응답상태
            methods: GET, POST  # 재시도 메소드
            backoff:
              firstBackoff: 500ms   #첫번째 재시도는 실패 후 0.5초 후 수행
              maxBackoff: 2000ms    #재시도 간격
              factor: 10            #firstBackoff * (factor^retries)가 재시도 간격임. maxBackoff보다 클 수는 없음.
              #exceptions:             # Connect가 안되는 경우에만 retry(POST일때는 불필요한 재시도 방지를 위해 설정하는게 좋음)
              #- java.net.ConnectException
      metadata: #현재 요청에 대해서만 Timeout 정의 시
        connect-timeout: 1000
        response-timeout: 3000

  # 그 외 application.yml에 설정 예제는 아래 페이지 참조
  # https://happycloud-lee.tistory.com/218
  #========================

  #========= Default Filters ========
  default-filters:
    #-- 인증 검사: JWT Token 유효성 검사
    #- AuthorizationHeaderFilter

    # Request Logging
    - name: PreLogger
      args:
        logging: true
        baseMessage: "######### Logging for Request ############"

    # Response Logging
    - name: PostLogger
      args:
        logging: true
        baseMessage: "######### Logging for Response ############"

    # 중요) 응답에 지정된 헤더가 중복되면 하나만 남김. 다른 필터와의 우선순위로 동작 안할 수 있으므로 가장 마지막에 지정
    - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
#=====================================



// File: scg/src/main/resources/application.yml
server:
  port: ${SERVER_PORT:19080}
spring:
  application:
    name: scg
  jwt:
    secret: ${JWT_SECRET:8O2HQ13etL2BWZvYOiWsJ5uWFoLi6NBUG8divYVoCgtHVvlk3dqRksMl16toztDUeBTSIuOOPvHIrYq11G2BwQ==}
  # -- Load banancer 설정 : 기본 L/B인 Ribbon비활성화
  cloud.loadbalancer:
    ribbon.enabled: false
    cache.enabled: true

  # -- Load Balancer의 캐시 타입 설정
  cache.type: caffeine

# Eureka client 설정
# hostname은 서버를 구별하는 유일한 값이면 됨. instanceId는 Eureka에 등록된느 ID임 (라우팅할 때 주소 아님)
# 라우팅 주소는 아래와 같이 결정됨
# - preferIpAddress: false -> http://hostname:nonSecurePort, https://hostname:securePort
# - preferIpAddress: true  -> http://ip:nonSecurePort, https://ip:securePort
# 연결되는 주소는 https://{eureka ingress host}/eureka/apps/{service id}의 결과에서 homepageUrl값임
# 생존신고를 하는 주기(lease-renewal-interval-in-seconds. 기본 30초)와
# 만료 간주 시간(Eureka서버가 몇 초 동안 생존 신고를 못 받으면 만료로 간주할 지 판단하는 시간. 기본 90초)을 적절히 정의
# preferIpAddress를 false로 하고 hostname에 k8s DNS주소를 설정하는 방식은 StatefulSet으로 배포하는 경우에만 동작함
# (Deployment로 배포한 Pod는 고유 주소가 생기지 않기 때문임)
eureka:
  instance:
    hostname: ${HOSTNAME:localhost}
    instanceId: ${HOSTNAME:localhost}:${SERVER_PORT:19080}
    preferIpAddress: true
    nonSecurePort: ${SERVER_PORT:19080}
    securePort: 443
    nonSecurePortEnabled: true
    securePortEnabled: false
    lease-renewal-interval-in-seconds: 5
    lease-expiration-duration-in-seconds: 10
  client:
    service-url:
      defaultZone: ${EUREKA_SERVERS:http://eureka1.127.0.0.1.nip.io:8761/eureka/,http://eureka2.127.0.0.1.nip.io:8762/eureka/}
    registryFetchIntervalSeconds: 5
    instanceInfoReplicationIntervalSeconds: 5

logging:
  level:
    root: INFO
    org.springframework.cloud.gateway: INFO

# -- Actuator
management:
  endpoints:
    web:
      exposure:
        include: health, info, env, mappings, routes

#========= 라우팅
spring.cloud.gateway:
  # CORS
  globalcors:
    allowedOrigins: ${ALLOWED_ORIGINS:http://localhost:3000}

  # Timeout
  httpclient:
    connect-timeout: 1000
    response-timeout: 3000

  # Routing
  # 모든 서비스가 k8s환경에서만 서비스 된다면 Eureka를 안 쓰고 k8s서비스로 L/B하는게 제일 좋음
  # 왜냐하면 k8s서비스의 liveness/readiness 체크하여 연결하는 기능을 사용할 수 있고, 불필요한 Eureka 네트워킹을 안할 수 있기 때문임
  # 이 예제에서는 Eureka에 Pod IP를 등록하고 SCG가 L/B하고 있음. 로그인요청만 Eureka연동하고, 나머지는 k8s서비스 사용함
  routes:
    - id: helloworld
      uri: lb://helloworld
      predicates:
        - Path=/hey/**
      filters:
        - RewritePath=/hey/(?<uri>.*), /${uri}

    - id: auth
      uri: lb://member-service
      predicates:
        - Path=/api/auth/**

    - id: member
      uri: lb://member-service
      predicates:
        - Path=/api/members/**

    - id: subrecommend
      uri: lb://subrecommend-service
      predicates:
        - Path=/api/subrecommend/**
      filters:
        - RewritePath=/api/subrecommend/(?<segment>.*), /api/${segment}

    - id: mysub
      uri: lb://mysub-service
      predicates:
        - Path=/api/my-subs/**

    - id: mygrp
      uri: lb://mygrp-service
      predicates:
        - Path=/api/my-groups/**

    - id: transfer
      uri: lb://transfer-service
      predicates:
        - Path=/api/transfer/**
      filters:
        - name: Retry
          args:
            retries: 5              # 재시도 횟수
            statuses: BAD_GATEWAY, INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE #재시도 할 응답상태
            methods: GET, POST  # 재시도 메소드
            backoff:
              firstBackoff: 500ms   #첫번째 재시도는 실패 후 0.5초 후 수행
              maxBackoff: 2000ms    #재시도 간격
              factor: 10            #firstBackoff * (factor^retries)가 재시도 간격임. maxBackoff보다 클 수는 없음.
              #exceptions:             # Connect가 안되는 경우에만 retry(POST일때는 불필요한 재시도 방지를 위해 설정하는게 좋음)
              #- java.net.ConnectException
      metadata: #현재 요청에 대해서만 Timeout 정의 시
        connect-timeout: 1000
        response-timeout: 3000

  # 그 외 application.yml에 설정 예제는 아래 페이지 참조
  # https://happycloud-lee.tistory.com/218
  #========================

  #========= Default Filters ========
  default-filters:
    #-- 인증 검사: JWT Token 유효성 검사
    #- AuthorizationHeaderFilter

    # Request Logging
    - name: PreLogger
      args:
        logging: true
        baseMessage: "######### Logging for Request ############"

    # Response Logging
    - name: PostLogger
      args:
        logging: true
        baseMessage: "######### Logging for Response ############"

    # 중요) 응답에 지정된 헤더가 중복되면 하나만 남김. 다른 필터와의 우선순위로 동작 안할 수 있으므로 가장 마지막에 지정
    - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
#=====================================



// File: scg/src/main/java/com/subride/sc/scg/ScgApplication.java
package com.subride.sc.scg;

import com.subride.sc.scg.lb.ServiceDiscovery;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
@EnableDiscoveryClient
@Slf4j
public class ScgApplication {
    public static void main(String[] args) {
        ApplicationContext context = SpringApplication.run(ScgApplication.class, args);

        log.info("************* Get services **************");
        ServiceDiscovery serviceDiscovery = context.getBean(ServiceDiscovery.class);

        log.info("*** MEMBER-SERVICE ***");
        serviceDiscovery.getServiceInstances("member-service");
    }
}


// File: scg/src/main/java/com/subride/sc/scg/CacheConfig.java
package com.subride.sc.scg;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CacheConfig {

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCaffeine(caffeineCacheBuilder());
        return cacheManager;
    }

    Caffeine<Object, Object> caffeineCacheBuilder() {
        return Caffeine.newBuilder()
                .initialCapacity(100)   //초기 캐시 크기: 몇개의 항목을 수용할 것인가?
                .maximumSize(500)       //최대 캐시 크기
                .expireAfterAccess(10, TimeUnit.MINUTES)    //캐시 제거 기준 시간: 마지막 접근 후 몇분동안 접근 없으면 삭제할 것인가?
                .weakKeys()     //캐시에 저장되는 각 항목에 대해 약한 참조로 설정. 어떤 항목을 참조하는 외부 객체가 사라지면 캐시에서도 그 항목이 사라지게 함
                .recordStats(); //캐시 통계 기록
    }
}


// File: scg/src/main/java/com/subride/sc/scg/config/SecurityConfig.java
package com.subride.sc.scg.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
@SuppressWarnings("unused")
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${spring.cloud.gateway.globalcors.allowedOrigins}")
    private String allowedOriginsStr;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(ServerHttpSecurity.CsrfSpec::disable);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        String[] allowedOrigins = allowedOriginsStr.split(",");
        logger.info("Configured Allowed Origins: {}", Arrays.toString(allowedOrigins));

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        logger.info("CORS Configuration: {}", configuration);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }
}

// File: scg/src/main/java/com/subride/sc/scg/lb/ServiceDiscovery.java
package com.subride.sc.scg.lb;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@SuppressWarnings("unused")
@Slf4j
public class ServiceDiscovery {
    private final DiscoveryClient discoveryClient;

    @Autowired
    public ServiceDiscovery(DiscoveryClient discoveryClient) {
        this.discoveryClient = discoveryClient;
    }

    public void getServiceInstances(String serviceId) {

        List<ServiceInstance> instances = discoveryClient.getInstances(serviceId);

        if (instances.isEmpty()) {
            log.info("No instances found for service: {}", serviceId);
        } else {
            log.info("Instances of {}", serviceId);
            for (ServiceInstance instance : instances) {
                log.info("Instance ID: {}", instance.getInstanceId());
                log.info("Host: {}", instance.getHost());
                log.info("Port: {}", instance.getPort());
                log.info("URI: {}", instance.getUri());
                log.info("---");
            }
        }
    }
}


// File: scg/src/main/java/com/subride/sc/scg/filter/logger/PostLogger.java
package com.subride.sc.scg.filter.logger;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import lombok.Getter;
import lombok.Setter;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class PostLogger extends AbstractGatewayFilterFactory<PostLogger.Config> {

    public PostLogger() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> chain.filter(exchange).then(Mono.fromRunnable(() -> {
            if (config.isLogging()) {
                logResponse(exchange, config);
            }
        }));
    }

    private void logResponse(ServerWebExchange exchange, Config config) {
        ServerHttpResponse response = exchange.getResponse();

        String logMessage = "Response logged: " +
                config.getBaseMessage() +
                "\n" +
                "Status code: " + response.getStatusCode() +
                "\n" +
                "Headers: " + response.getHeaders() +
                "\n";

        log.info(logMessage);
    }

    @Getter
    @Setter
    public static class Config {
        private String baseMessage = "PostLogger Filter";
        private boolean logging = true;
    }
}


// File: scg/src/main/java/com/subride/sc/scg/filter/logger/PreLogger.java
package com.subride.sc.scg.filter.logger;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;
import org.springframework.web.server.ServerWebExchange;

@Slf4j
@Component
public class PreLogger extends AbstractGatewayFilterFactory<PreLogger.Config> {
    public PreLogger() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        //grab configuration from Config object
        return (exchange, chain) -> {
            if (config.isLogging()) {
                logRequest(exchange, config);
            }

            ServerHttpRequest.Builder builder = exchange.getRequest().mutate();
            return chain.filter(exchange.mutate().request(builder.build()).build());
        };
    }
    private void logRequest(ServerWebExchange exchange, Config config) {
        ServerHttpRequest request = exchange.getRequest();

        String logMessage = "Request logged: " +
                config.getBaseMessage() +
                "\n" +
                "Method: " + request.getMethod() +
                "\n" +
                "Path: " + request.getURI().getPath() +
                "\n" +
                "Headers: " + request.getHeaders() +
                "\n";

        log.info(logMessage);
    }

    @Getter
    @Setter
    public static class Config {
        private String baseMessage;
        private boolean logging;

    }
}

// File: scg/src/main/java/com/subride/sc/scg/filter/auth/JwtUtil.java
package com.subride.sc.scg.filter.auth;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@SuppressWarnings("unused")
public class JwtUtil {
    private final SecretKey secretKey;

    public JwtUtil(@Value("${spring.jwt.secret}")String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS512.key().build().getAlgorithm());
    }

    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}

// File: scg/src/main/java/com/subride/sc/scg/filter/auth/AuthorizationHeaderFilter.java
package com.subride.sc.scg.filter.auth;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
@SuppressWarnings("unused")
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    @Autowired
    private JwtUtil jwtUtil;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {
        // application.yml 파일에서 지정한 filer의 Argument값을 받는 부분
    }

    @Override
    public GatewayFilter apply(Config config) {
        //log.info("************* Check Authorization");
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (request.getURI().getPath().startsWith("/api/auth") ||
                    request.getURI().getPath().startsWith("/api/subrecommend/detail")) {
                log.info("*** Skip check authentication: "+request.getURI().getPath());
                return chain.filter(
                        exchange.mutate().request(
                                exchange.getRequest().mutate().build()
                        ).build());
            }

            List<String> authHeaders = request.getHeaders().get("Authorization");

            if (authHeaders == null || authHeaders.isEmpty()) {
                return onError(exchange, HttpStatus.BAD_REQUEST, "100");
            }

            String token = authHeaders.get(0).substring(7);
            String username;

            try {
                username = jwtUtil.getUsername(token);
            } catch (ExpiredJwtException ex) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "200");
            } catch (Exception ex) {
                return onError(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "500");
            }

            exchange.getRequest().mutate().header("X-Authorization-Id", username).build();

            return chain.filter(
                    exchange.mutate().request(
                            exchange.getRequest().mutate().build()
                    ).build());

        };
    }

    private Mono<Void> onError(@NonNull ServerWebExchange exchange, @NonNull HttpStatus status, @NonNull String errorCode) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorResponse = "{\"errorCode\": \"" + errorCode + "\"}";
        byte[] bytes = errorResponse.getBytes();

        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }

    @Bean
    public ErrorWebExceptionHandler tokenValidation() {
        return new JwtTokenExceptionHandler();
    }

    public static class JwtTokenExceptionHandler implements ErrorWebExceptionHandler {
        @Override
        @NonNull
        public Mono<Void> handle(@NonNull ServerWebExchange exchange, @NonNull Throwable ex) {
            HttpStatus status;
            String errorCode;

            if (ex instanceof NullPointerException) {
                status = HttpStatus.BAD_REQUEST;
                errorCode = "100";
            } else if (ex instanceof ExpiredJwtException) {
                status = HttpStatus.UNAUTHORIZED;
                errorCode = "200";
            } else {
                status = HttpStatus.INTERNAL_SERVER_ERROR;
                errorCode = "500";
            }

            exchange.getResponse().setStatusCode(status);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            String errorResponse = "{\"errorCode\": \"" + errorCode + "\"}";
            byte[] bytes = errorResponse.getBytes();

            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        }
    }
}

// File: /Users/ondal/home/workspace/sc/settings.gradle
rootProject.name = 'sc'
include 'config'
include 'eureka'
include 'scg'



// File: /Users/ondal/home/workspace/sc/build.gradle
plugins {
	id 'java'
	id 'org.springframework.boot' version '3.2.6'
	id 'io.spring.dependency-management' version '1.1.5'
	id "org.sonarqube" version "5.0.0.4638" apply false		//apply false 해야 서브 프로젝트에 제대로 적용됨
}

allprojects {
	group = 'com.cna'
	version = '0.0.1-SNAPSHOT'

	apply plugin: 'java'
	apply plugin: 'io.spring.dependency-management'

	java {
		sourceCompatibility = '17'
	}

	repositories {
		mavenCentral()
	}

	dependencies {
		implementation 'org.springframework.boot:spring-boot-starter'
		implementation 'org.springframework.boot:spring-boot-starter-actuator'

		compileOnly 'org.projectlombok:lombok'
		annotationProcessor 'org.projectlombok:lombok'

		testImplementation 'org.springframework.boot:spring-boot-starter-test'
		testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
	}

	dependencyManagement {
		imports {
			mavenBom "org.springframework.cloud:spring-cloud-dependencies:2023.0.2"
		}
	}

	tasks.named('test') {
		useJUnitPlatform()
	}
}

subprojects {
	apply plugin: 'org.springframework.boot'
	apply plugin: 'org.sonarqube'
}


