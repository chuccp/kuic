# kuic
基于 quic-go 实现同一端口，同时当服务端又当客户端，从而实现nat穿透

使用前可能需要

go mod edit -replace github.com/quic-go/quic-go=github.com/chuccp/quic-go@v0.0.1