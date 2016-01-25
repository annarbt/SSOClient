package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/RobotsAndPencils/go-saml"
	"github.com/gorilla/mux"
)

import "text/template"

var sp = saml.ServiceProviderSettings{
	PublicCertPath:              "frntn-x509-san.crt",
	PrivateKeyPath:              "frntn-x509-san.key",
	IDPSSOURL:                   "http://192.168.244.160:8080/sso",
	IDPSSODescriptorURL:         "http://192.168.244.160:8080/issuer",
	IDPPublicCertPath:           "frntn-x509-san.crt", //Private key to sign and pusblic key to verify. The reason for IdP providing you its certificate is for SP to validate the signed SAML responses sent by the IdP.
	SPSignRequest:               true,
	AssertionConsumerServiceURL: "http://192.168.244.160:8000/acs", //Destination on Response, will check against this
}

func main() {

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", Index)
	router.HandleFunc("/login", Login)
	router.HandleFunc("/acs", ACS).Methods("POST")

	log.Fatal(http.ListenAndServe(":8000", router))

}

func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Println("This is the SSOClient")
}

func ACS(w http.ResponseWriter, r *http.Request) {
	encodedXML := r.FormValue("SAMLResponse")

	//WTF is httpcommon
	//fmt.Println("ACS Hit", encodedXML)

	if encodedXML == "" {
		//httpcommon.SendBadRequest(w, "SAMLResponse form value missing")
		w.WriteHeader(500)
		w.Write([]byte("SAMLResponse form value missing"))
		return
	}

	response, err := saml.ParseEncodedResponse(encodedXML)
	if err != nil {
		//httpcommon.SendBadRequest(w, "SAMLResponse parse: "+err.Error())
		w.WriteHeader(500)
		w.Write([]byte("SAMLResponse parse: " + err.Error()))
		return
	}

	//	fmt.Println("Response", response)

	err = response.Validate(&sp) //publicCertPath is sp
	if err != nil {
		//httpcommon.SendBadRequest(w, "SAMLResponse validation: "+err.Error())
		w.WriteHeader(500)
		w.Write([]byte("SAMLResponse validation: " + err.Error()))
		return
	}

	samlID := response.GetAttribute("email")
	if samlID == "" {
		//httpcommon.SendBadRequest(w, "SAML attribute identifier uid missing")
		w.Write([]byte("SAML attribute identifier uid missing"))
		return
	}

	w.Write([]byte("Hello " + samlID))

	//...
}

//Login user with IdP
func Login(w http.ResponseWriter, r *http.Request) {

	sp.Init()

	// generate the AuthnRequest and then get a base64 encoded string of the XML
	authnRequest := sp.GetAuthnRequest()
	b64XML, err := authnRequest.EncodedSignedString(sp.PrivateKeyPath)
	if err != nil {
		panic(err)
	}

	// for convenience, get a URL formed with the SAMLRequest parameter
	//The third aparameter the relay state
	relaystate := ""
	url, err := saml.GetAuthnRequestURL(sp.IDPSSOURL, b64XML, relaystate)
	if err != nil {
		panic(err)
	}

	// below is bonus for how you might respond to a request with a form that POSTs to the IdP
	data := struct {
		Base64AuthRequest string
		URL               string
	}{
		Base64AuthRequest: b64XML,
		URL:               url,
	}

	t := template.New("saml")
	t, err = t.Parse("<html><body style=\"display: none\" onload=\"document.frm.submit()\"><form method=\"post\" name=\"frm\" action=\"{{.URL}}\"><input type=\"hidden\" name=\"SAMLRequest\" value=\"{{.Base64AuthRequest}}\" /><input type=\"submit\" value=\"Submit\" /></form></body></html>")

	// how you might respond to a request with the templated form that will auto post
	t.Execute(w, data)
}

//The Service Provider (SP) receives metadata from the Identity Provider (IdP),
//parses it and sends back SP Metadata XML to the IdP.
//Metadata can be either generated automatically upon first request to the
//service, or it can be pre-created (see Chapter 11, Sample application). Once
//created metadata needs to be provided to the identity providers with whom we
//want to establish trust.

func samlMetadataHandler(sp *saml.ServiceProviderSettings) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md, err := sp.GetEntityDescriptor()
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte("Error: " + err.Error()))
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(md))
	})
}
