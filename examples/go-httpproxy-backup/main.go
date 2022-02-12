/*
go-httpproxy-demo is an example for HTTP and HTTPS web proxy.

Connect through HTTP proxy to HTTP:
curl -x "http://test:1234@localhost:8080" http://httpbin.org/get?a=b

Connect through HTTP proxy to HTTPS with MITM:
curl --insecure -x "http://test:1234@localhost:8080" https://httpbin.org/get?a=b

Connect through HTTPS proxy to HTTP:
curl --proxy-insecure -x "https://test:1234@localhost:8443" http://httpbin.org/get?a=b

Connect through HTTPS proxy to HTTPS with MITM:
curl --proxy-insecure --insecure -x "https://test:1234@localhost:8443" https://httpbin.org/get?a=b

*/
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Archie1978/httpproxy"
)

var logErr = log.New(os.Stderr, "ERR: ", log.LstdFlags)

func OnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	// Log errors.
	logErr.Printf("%s: %s [%s]", where, err, opErr)
}

func OnAccept(ctx *httpproxy.Context, w http.ResponseWriter,
	r *http.Request) bool {
	// Handle local request has path "/info"
	if r.Method == "GET" && !r.URL.IsAbs() && r.URL.Path == "/info" {
		w.Write([]byte("This is go-httpproxy."))
		return true
	}
	return false
}

func OnAuth(ctx *httpproxy.Context, authType string, user string, pass string) bool {
	// Auth test user.
	if user == "test" && pass == "1234" {
		return true
	}
	return false
}

func OnConnect(ctx *httpproxy.Context, host string) (
	ConnectAction httpproxy.ConnectAction, newHost string) {
	// Apply "Man in the Middle" to all ssl connections. Never change host.
	return httpproxy.ConnectMitm, host
}

func OnRequest(ctx *httpproxy.Context, req *http.Request) (
	resp *http.Response) {
	// Log proxying requests.
	log.Printf("INFO: Proxy %d %d: %s %s", ctx.SessionNo, ctx.SubSessionNo, req.Method, req.URL.String())
	return
}

func OnResponse(ctx *httpproxy.Context, req *http.Request,
	resp *http.Response) {
	// Add header "Via: go-httpproxy".
	resp.Header.Add("Via", "go-httpproxy")
}


// DefaultCaCert provides default CA certificate.
var DefaultCaCert = []byte(`-----BEGIN CERTIFICATE-----
MIIFkzCCA3ugAwIBAgIJAKEbW2ujNjX9MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNV
BAYTAlRSMREwDwYDVQQIDAhJc3RhbmJ1bDEVMBMGA1UECgwMZ28taHR0cHByb3h5
MRIwEAYDVQQLDAlodHRwcHJveHkxEzARBgNVBAMMCmdpdGh1Yi5jb20wHhcNMTgw
MjAyMTMwNTE3WhcNMzgwMTI4MTMwNTE3WjBgMQswCQYDVQQGEwJUUjERMA8GA1UE
CAwISXN0YW5idWwxFTATBgNVBAoMDGdvLWh0dHBwcm94eTESMBAGA1UECwwJaHR0
cHByb3h5MRMwEQYDVQQDDApnaXRodWIuY29tMIICIjANBgkqhkiG9w0BAQEFAAOC
Ag8AMIICCgKCAgEA18cwaaZzhdDEpUXpR9pkYRqsSdT30WhynFhFtcaBOf4eYdpt
AJWL2ipo3Ac6bh+YgWfywG4prrSfWOJl+dQ59w439vLek/waBcEeFx+wJ6PFu0ur
84T0vrCaiXaHfUA6c9hiuoHCNFkGgO/q1gdmGXD27Sn9MKyqVprXhqO29Kz9lu4p
T6FpEarEevfq8MvYtg+73ESwCwv10yITFVWpqvO2LkShJ39uvJ3EN4Y44SXQOT0m
za71dL9OcWeTzx0mJKmsIZzzSfNKPgqn8TJzHa1u3DhO9L+GN9VNz5bCPjOmjM2z
dS5ditgyxTY3YaTsR/G8SW9drEeD3hbjx+1/9W/XURacfnBdNUcIUyvUPwV3V5Ht
IIJR4bz/vIQ/8QFbTi5ddS69bmvJ6PhI2pSc/RxWQVMLjc+cmsUMHiKtoM9QAn7C
6/As+YLBQYZ0+sJUcFFcIayVzi8bwQ09yY8R0U5xXGvDYapVJUMZufy8UKOQxAP2
Y2wEJAEFxUPoMozTlkxwZdvhDq/JwdCuc94cXLQ8oCu8zVgajb8WfYPKgwviHyZ+
2rH7JDuumzigo1dqMSNHUPPohnsjAeNpXFu5bvTRAVLEO4aggPHtlyBDilxT1Bar
oyC3UQzcjvD8/yYnO9BTJXNNBfNbTVxi6UqMUMDnJccuZOXO02DbW8uI/hECAwEA
AaNQME4wHQYDVR0OBBYEFIGx22SSLgTh1NCzKxg4uTUfahqiMB8GA1UdIwQYMBaA
FIGx22SSLgTh1NCzKxg4uTUfahqiMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggIBAIMxUgLHrc1e4JDsttJfU9BlWI3y2kX90ss1r84pUq+Cg9pneRl5iq6K
xFVg1dP5lSQAhn0EQvGLfcoCRO98u+HoWCIkJTFNZppVQY+LXNXf1kfVkFNQzonU
8i5FKzo3HDXsSPTCLN7TctnMg31OsaIO75ryIPjmkUZe9xn9g0qvDa8kMrNwRCKX
N9Xk9uXUHhM/Mf+3gknAiEBfjFnWIfw87y63jI4c98XBhxbGzcoonxNNa0ql7yrx
knQ7ST2huX4HTvN//lzmgcNWzvPg/sdbr9JTFZyPKCcWGrLsG2uN2g1/P6Mi1T/M
ToXw/R9Lu0AK2h1o7FJjoJndokH7Ha0fShpCbfEYieTNvZbwkpzMYR8+IEFPkvKm
Dox1P6CqdLNyHBikLCxcQM7AQmuijdciXyYwHOVr/1r0jZqM0zI51t9Kyuw5kn0K
b2Ir0ERgrXx8eMQBrW6eseIAtqSHXDK+RKkU38xnYTBe6Jbg6r1F8zk/mzUye4IO
34LC38AY9if1kCwegkEFMmaTY8Z4YD3sxmezvEbxeWaHk4TfMGISmKQ3U41T2yEJ
Ii9Vb07WDMQXou0ZZs7rnjAKo+sfFElTFewtS1wif4ZYBUJN1ln9G8qKaxbAiElm
MgzNfZ7WlnaJf2rfHJbvK9VqJ9z6dLRYPjCHhakJBtzsMdxysEGJ
-----END CERTIFICATE-----`)

// DefaultCaKey provides default CA key.
var DefaultCaKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)

func main() {
	log.SetOutput(os.Stdout)
	log.Print("Started")

	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGTERM)

	// Backup certificate
	var backupCertificate httpproxy.BackupCertificateDisk
	backupCertificate.PathCertificates="certs"

	// Create a new proxy with default certificate pair.
	signer := httpproxy.NewCaSignerCache(1024)
	signer.BackupCertificate = &backupCertificate
	prx, _ := httpproxy.NewProxyCertSigner(DefaultCaKey, DefaultCaKey, signer)

	// Set proxy handlers.
	prx.OnError = OnError
	prx.OnAccept = OnAccept
	prx.OnAuth = OnAuth
	prx.OnConnect = OnConnect
	prx.OnRequest = OnRequest
	prx.OnResponse = OnResponse
	//prx.MitmChunked = false

	server := &http.Server{
		Addr:         ":8080",
		Handler:      prx,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	listenErrChan := make(chan error)
	go func() {
		listenErrChan <- server.ListenAndServe()
	}()
	log.Printf("Listening HTTP %s", server.Addr)

	cert, _ := tls.X509KeyPair(httpproxy.DefaultCaCert, httpproxy.DefaultCaKey)
	serverHTTPS := &http.Server{
		Addr:         ":8443",
		Handler:      prx,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionSSL30,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			Certificates: []tls.Certificate{cert},
		},
	}
	listenHTTPSErrChan := make(chan error)
	go func() {
		listenHTTPSErrChan <- serverHTTPS.ListenAndServeTLS("", "")
	}()
	log.Printf("Listening HTTPS %s", serverHTTPS.Addr)

mainloop:
	for {
		select {
		case <-sigChan:
			break mainloop
		case listenErr := <-listenErrChan:
			if listenErr != nil && listenErr == http.ErrServerClosed {
				break mainloop
			}
			log.Fatal(listenErr)
		case listenErr := <-listenHTTPSErrChan:
			if listenErr != nil && listenErr == http.ErrServerClosed {
				break mainloop
			}
			log.Fatal(listenErr)
		}
	}

	shutdown := func(srv *http.Server, wg *sync.WaitGroup) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		srv.SetKeepAlivesEnabled(false)
		if err := srv.Shutdown(ctx); err == context.DeadlineExceeded {
			log.Printf("Force shutdown %s", srv.Addr)
		} else {
			log.Printf("Graceful shutdown %s", srv.Addr)
		}
		wg.Done()
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go shutdown(server, wg)
	wg.Add(1)
	go shutdown(serverHTTPS, wg)
	wg.Wait()

	log.Println("Finished")
}
