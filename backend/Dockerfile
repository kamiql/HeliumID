# syntax=docker/dockerfile:1.7

FROM gradle:9-jdk25 AS build

WORKDIR /app

COPY gradlew .
COPY gradle gradle
COPY settings.gradle.kts .
COPY build.gradle.kts .

RUN --mount=type=cache,target=/home/gradle/.gradle \
    ./gradlew dependencies --no-daemon

COPY . .

RUN --mount=type=cache,target=/home/gradle/.gradle \
    ./gradlew installDist --no-daemon

FROM eclipse-temurin:25-jre

WORKDIR /app

COPY --from=build /app/build/install/HeliumID .

EXPOSE 8080

CMD ["bin/HeliumID"]