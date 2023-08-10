package kuic

import (
	"context"
	"github.com/quic-go/quic-go"
)

type Connection interface {
	AcceptStream() (quic.Stream, error)
	OpenStreamSync() (quic.Stream, error)
}
type connection struct {
	connection quic.Connection
	context    context.Context
}

func (connection *connection) AcceptStream() (quic.Stream, error) {
	return connection.connection.AcceptStream(connection.context)
}
func (connection *connection) OpenStreamSync() (quic.Stream, error) {
	return connection.connection.OpenStreamSync(connection.context)
}
func createConnection(conn quic.Connection, context context.Context) *connection {
	return &connection{connection: conn, context: context}
}
