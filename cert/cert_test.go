package cert

import (
	"testing"
)

func TestCrt(t *testing.T) {

	err := CreateCertGroup(nil, "server.cer", "server.crt", "server.key")
	if err != nil {
		return
	}
	err = CreateCertGroup(nil, "client.cer", "client.crt", "client.key")
	if err != nil {
		return
	}
	t.Log(err)

}
