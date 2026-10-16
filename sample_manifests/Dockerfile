# Sample Vulnerable Microservice Dockerfile for VulnWatch Security Testing
FROM openjdk:11-jre-slim

LABEL maintainer="sgp-security-team@example.com"
LABEL version="1.0"

USER root
WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    bash \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Application with legacy vulnerable components
COPY target/payment-service.jar /app/app.jar

ENV PORT=8080
ENV ENVIRONMENT=production

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
