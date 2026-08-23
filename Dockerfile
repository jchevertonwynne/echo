FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
# No dependencies, so no go.sum and nothing to download.
COPY go.mod ./
COPY . .
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/echo .

# scratch: a static binary with no assets needs nothing else. No shell, no
# libc, nothing to patch. No tzdata either — this app has no wall-clock logic.
FROM scratch
COPY --from=build /out/echo /echo
USER 65532:65532
EXPOSE 8092
ENTRYPOINT ["/echo"]
CMD ["-addr", ":8092"]
