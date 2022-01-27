# Go HTTP proxy server library

[![GoDoc](https://godoc.org/github.com/go-httpproxy/httpproxy?status.svg)](https://godoc.org/github.com/go-httpproxy/httpproxy)

Package httpproxy provides a customizable HTTP proxy; supports HTTP, HTTPS through
CONNECT. And also provides HTTPS connection using "Man in the Middle" style
attack.

It's easy to use. `httpproxy.Proxy` implements `Handler` interface of `net/http`
package to offer `http.ListenAndServe` function.

## Installing

```sh
go get -u github.com/Archie1978/httpproxy
# or origin
go get -u gopkg.in/httpproxy.v1
```

## Usage

Library has two significant structs: Proxy and Context.

### Proxy struct

```go
// Proxy defines parameters for running an HTTP Proxy. It implements
// http.Handler interface for ListenAndServe function. If you need, you must
// set Proxy struct before handling requests.
type Proxy struct {
	// Session number of last proxy request.
	SessionNo int64

	// RoundTripper interface to obtain remote response.
	// By default, it uses &http.Transport{}.
	Rt http.RoundTripper

	// Certificate key pair.
	Ca tls.Certificate

	// User data to use free.
	UserData interface{}

	// Error callback.
	OnError func(ctx *Context, where string, err *Error, opErr error)

	// Accept callback. It greets proxy request like ServeHTTP function of
	// http.Handler.
	// If it returns true, stops processing proxy request.
	OnAccept func(ctx *Context, w http.ResponseWriter, r *http.Request) bool

	// Auth callback. If you need authentication, set this callback.
	// If it returns true, authentication succeeded.
	OnAuth func(ctx *Context, authType string, user string, pass string) bool

	// Connect callback. It sets connect action and new host.
	// If len(newhost) > 0, host changes.
	OnConnect func(ctx *Context, host string) (ConnectAction ConnectAction,
		newHost string)

	// Request callback. It greets remote request.
	// If it returns non-nil response, stops processing remote request.
	OnRequest func(ctx *Context, req *http.Request) (resp *http.Response)

	// Response callback. It greets remote response.
	// Remote response sends after this callback.
	OnResponse func(ctx *Context, req *http.Request, resp *http.Response)

	// If ConnectAction is ConnectMitm, it sets chunked to Transfer-Encoding.
	// By default, true.
	MitmChunked bool

	// HTTP Authentication type. If it's not specified (""), uses "Basic".
	// By default, "".
	AuthType string
}
```

### Context struct

```go
// Context keeps context of each proxy request.
type Context struct {
	// Pointer of Proxy struct handled this context.
	// It's using internally. Don't change in Context struct!
	Prx *Proxy

	// Session number of this context obtained from Proxy struct.
	SessionNo int64

	// Sub session number of processing remote connection.
	SubSessionNo int64

	// Original Proxy request.
	// It's using internally. Don't change in Context struct!
	Req *http.Request

	// Original Proxy request, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectReq *http.Request

	// Action of after the CONNECT, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectAction ConnectAction

	// Remote host, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectHost string

	// User data to use free.
	UserData interface{}
}
```

## Examples

For more examples, examples/

### examples/go-httpproxy-simple
Create key
openssl genrsa -des3 -out myCA.key 2048
Decode key
openssl rsa -in myCA.key -out myCA.key.clear
Create certificate
openssl req -config openssl.cnf       -key myCA.key.clear       -new -x509 -days 7300 -sha256 -extensions v3_ca       -out ca.cert.pem


openssl.cnf
```
 OpenSSL root CA configuration file.
# Copy to `/root/ca/openssl.cnf`.

[ ca ]
# `man ca`
default_ca =  My CA TLS

[ CA_default ]
# Directory and file locations.
dir               = /home/ron/workspace/go/src/idesi.fr/dev/proxy_http_1.0 
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = GB
stateOrProvinceName_default     = England
localityName_default            =
0.organizationName_default      = COMPANY (SA)
organizationalUnitName_default  = SECURITY GROUP
emailAddress_default            = foo@foo.gb

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning



```



```go
package main

import (
	"log"
	"net/http"

	"github.com/go-httpproxy/httpproxy"
)

func OnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	// Log errors.
	log.Printf("ERR: %s: %s [%s]", where, err, opErr)
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
	log.Printf("INFO: Proxy: %s %s", req.Method, req.URL.String())
	return
}

func OnResponse(ctx *httpproxy.Context, req *http.Request,
	resp *http.Response) {
	// Add header "Via: go-httpproxy".
	resp.Header.Add("Via", "go-httpproxy")
}

func main() {
	// Create a new proxy with default certificate pair.
	prx, _ := httpproxy.NewProxy()

	// Set handlers.
	prx.OnError = OnError
	prx.OnAccept = OnAccept
	prx.OnAuth = OnAuth
	prx.OnConnect = OnConnect
	prx.OnRequest = OnRequest
	prx.OnResponse = OnResponse

	// Listen...
	http.ListenAndServe(":8080", prx)
}
```
