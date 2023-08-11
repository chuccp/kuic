package http3

import (
	"github.com/chuccp/kuic/cert"
	"github.com/quic-go/quic-go/http3"
	"log"
	"net/http"
	"testing"
)

func TestServer(t *testing.T) {

	keyPem := "key2.PEM"
	certPem := "cert2.PEM"

	err := cert.CreateOrReadCert(keyPem, certPem)
	if err != nil {
		log.Println(err)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(response http.ResponseWriter, re *http.Request) {
		response.Write([]byte("1111111"))
	})
	err = http3.ListenAndServe("0.0.0.0:2315", certPem, keyPem, mux)
	if err != nil {
		log.Println(err)
		return
	}

	//err := http3.ListenAndServeQUIC()
	//if err != nil {
	//	return
	//}

	//udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 2315})
	//if err != nil {
	//	return
	//}
	//
	//mux := http.NewServeMux()
	//mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
	//	w.Write([]byte("foobar"))
	//})
	//s.Handler = mux
	//
	//err = s.Serve(udp)
	//if err != nil {
	//	log.Println(err)
	//	return
	//}
}
