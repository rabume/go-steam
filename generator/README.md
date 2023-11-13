# Generator for steamlang and protobuf

We generate Go code from SteamKit protocol descriptors, namely `steamlang` files and protocol buffer files.

## Dependencies

1.  Init latest submodules: `git submodule update`.

2.  Get latest submodules: `git submodule update --recursive --remote`.

3.  Install [`protoc`](https://developers.google.com/protocol-buffers/docs/downloads), the protocol buffer compiler.

    ```
    ✗ protoc --version
    libprotoc 24.3
    ```

4.  Install `protoc-gen-go`: `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`

    ```
    ✗ protoc-gen-go --version
    protoc-gen-go v1.31.0
    ```

5.  Install the .NET Core SDK 6.0.

## Execute generator

Execute `go run generator.go clean proto steamlang` to clean build files, then build protocol buffer files and then build steamlang files.
