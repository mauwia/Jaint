FROM eclipse-temurin:17-jdk AS build
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 \
    apt-get update && apt-get install -y maven && \
    mvn -B -DskipTests package

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /workspace/target/javasecscan-*.jar /app/javasecscan.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/javasecscan.jar"]
