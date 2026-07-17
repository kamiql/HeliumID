FROM gradle:9-jdk25 AS build

WORKDIR /app

COPY . .

RUN gradle installDist --no-daemon

FROM eclipse-temurin:25-jre

WORKDIR /app

COPY --from=build /app/build/install/* .

EXPOSE 8080

CMD ["bin/HeliumID"]