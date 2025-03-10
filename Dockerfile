# Stage 1: Builder stage using Gradle
FROM gradle:7.6.0-jdk17 AS builder
WORKDIR /app
# Copy all project files (adjust as needed for caching)
COPY . .
# Build the project using Gradle (the jar will be in build/libs)
RUN ./gradlew assemble

FROM ubuntu:24.04

ENV TRACCAR_VERSION=6.5

WORKDIR /opt/traccar

# Install required packages
RUN set -ex; \
    apt-get update; \
    TERM=xterm DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
      openjdk-17-jre-headless \
      unzip \
      wget; \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy your application jar and directories
COPY setup/out/data ./data
COPY setup/out/logs ./logs
COPY target/lib ./lib

# Copy the built jar from the builder stage
COPY --from=builder /app/target/tracker-server.jar ./tracker-server.jar

# media, conf, schema, templates and web are from NFS
# Set the entrypoint to run your jar with config file
ENTRYPOINT ["java", "-Xms1g", "-Xmx1g", "-Djava.net.preferIPv4Stack=true"]
CMD ["-jar", "tracker-server.jar", "conf/traccar.xml"]