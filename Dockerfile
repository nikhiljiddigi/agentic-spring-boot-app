# ---------- Stage 1: Build ----------
FROM eclipse-temurin:17-jdk AS build

# Set workdir
WORKDIR /app

# Copy Gradle/Maven build files and source
COPY . .

# Build the Spring Boot JAR (use Gradle)
RUN ./gradlew clean bootJar --no-daemon

# ---------- Stage 2: Runtime ----------
FROM eclipse-temurin:17-jre

WORKDIR /app
# Copy built JAR from previous stage
COPY --from=build /app/build/libs/*.jar app.jar

# Expose default port
EXPOSE 8080

# Use non-root user for security
RUN useradd spring
USER spring

# Run the Spring Boot app
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
