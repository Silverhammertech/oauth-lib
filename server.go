package oauth_lib

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/codegangsta/negroni"
)

const (
	CURRENT_DEBUG = false
	DEBUG         = false
	OLD_DEBUG     = false
)

const VERSION = "0.0.11"

const (
	DISABLE_TIMEOUT = false
	ENABLE_TIMEOUT  = true
)

const SYSTEM_SITE = "service"

var (
	SCOPES       = []string{""}
	oauthEnabled = false
)

var CLIENT_ID string
var CLIENT_SECRET string
var SERVICE_CREDENTIAL string
var CLIENT_ZONE string
var uaaHostName string

type MyJWT struct {
	UserName         string   `json:"user_name"`
	Error            string   `json:"error"`
	ErrorDescription string   `json:"error_description"`
	Scope            []string `json:"scope"`
}

func init() {

	oauthKeyCache = make(map[string]string)

	uaa_client_id := "uaa_client_id"
	uaa_client_secret := "uaa_client_secret"
	uaaHostName = "uaa_url"

	if uaa_client_id != "" && !strings.ContainsAny(uaa_client_id, "[]") {
		CLIENT_ID = uaa_client_id
	}
	if uaa_client_secret != "" && !strings.ContainsAny(uaa_client_secret, "[]") {
		CLIENT_SECRET = uaa_client_secret
	}
	if uaaHostName == "" {
		log.Println("Error: No uaa_url specified in Environment")
	}

	//fmt.Println("DBG-> CLIENT_ID: ",CLIENT_ID,"; CLIENT_SECRET: ",CLIENT_SECRET)

	//  calculate SERVICE_CREDENTIAL
	message := CLIENT_ID + ":" + CLIENT_SECRET
	uaa_service_credential := base64.StdEncoding.EncodeToString([]byte(message))
	SERVICE_CREDENTIAL = uaa_service_credential

	CLIENT_ZONE = ""
}

func GetVersion() (version string) {
	return VERSION
}

func ParseTokenRequest(r *http.Request) string {
	token := r.Header.Get("Authorization")[7:]
	return token
}

func GetAuthenticationToken(r *http.Request) (token string, exists bool) {

	exists = true
	if len(r.Header.Get("Authorization")) == 0 {
		exists = false
		return
	}

	token = ParseTokenRequest(r)
	return
}

func GetAuthenticationScopes(r *http.Request) (scopes []string, exists bool) {

	exists = true
	if len(r.Header.Get("Authorization")) == 0 {
		exists = false
		return
	}

	token := ParseTokenRequest(r)
	claims, _ := decode(token)

	scopes = claims.Scope
	return
}

func GetAuthenticationSites(r *http.Request) (sites []string, exists bool) {

	scopes, exists := GetAuthenticationScopes(r)

	for s := range scopes {
		site := scopes[s]
		idx := strings.Index(site, "tenant")
		if idx >= 0 {
			slist := strings.Split(site, ".")
			site = slist[len(slist)-1]
			sites = append(sites, site)
		}
	}

	return
}

func CheckAuthentication(r *http.Request) (statusCode int, error string) {
	var myJWT MyJWT
	var claims ClaimSet

	error = ""
	statusCode = http.StatusUnauthorized //  401

	host_url := uaaHostName + "/check_token"
	if uaaHostName == "" {
		error = "Error: No uaa_url specified in Environment"
		log.Println(error)
		return
	}

	token, exists := GetAuthenticationToken(r)
	if !exists {
		error = "Error: Authentication token does not exist"
		log.Println(error)
		return
	}

	//  check for FastToken processing here??
	disabled := os.Getenv("DISABLE_FAST_TOKEN_CHECK")
	if (disabled == "") || (disabled != "true") {
		if FastTokenVerify(token) {
			if DEBUG {
				fmt.Println("OAuth2_DBG-> Verified Request Authorization using FastToken")
			}
			statusCode = http.StatusOK
			return
		}
	}

	data := url.Values{}
	data.Set("token", token)

	client := &http.Client{}
	req, err := http.NewRequest("POST", host_url, bytes.NewBufferString(data.Encode()))
	if err != nil {
		if DEBUG {
			fmt.Println("OAuth2_DBG-> http.NewRequest() failed")
		}
	}

	req.Header.Add("Authorization", "Basic "+SERVICE_CREDENTIAL)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp == nil || err != nil {
		if DEBUG {
			fmt.Println("OAuth2_DBG-> client.Do() failed")
		}
		return
	}

	if DEBUG {
		fmt.Println("DBG-> resp: ", resp)
	}

	input, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1048576))
	fmt.Println("DBG-> body: ", string(input))

	//  need to process body info here
	err = json.Unmarshal(input, &myJWT)
	if err != nil {
		fmt.Printf("Unmarshal error:  %s  ", err.Error())
		return
	} else if myJWT.Error != "" {
		fmt.Println("DBG-> Verification Error: ", myJWT.Error)
		error = myJWT.Error
		return
	}

	//  need to parse expiry and possibly scopes
	err = json.Unmarshal(input, &claims)
	if err != nil {
		error = fmt.Sprintf("Unmarshal error:  %s  ", err.Error())
		log.Println(error)
		return
	}

	valid := ValidateClaimSet(claims)
	if DEBUG {
		fmt.Println("DBG-> valid: ", valid)
	}
	if valid {
		statusCode = http.StatusOK
	}

	if DEBUG {
		fmt.Println("OAuth2_DBG-> Verified Request Authorization")
	}
	return
}

func IsAuthenticated() negroni.Handler {
	au := func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

		statusCode, err := CheckAuthentication(r)
		if statusCode != http.StatusOK {
			ct := r.Header.Get("Content-Type")

			//Handle the different response codes appropriately
			w.WriteHeader(statusCode)

			if strings.Contains(strings.ToLower(ct), "json") {
				w.Header().Set("Content-Type", "application/json; charset=UTF-8")
				fmt.Fprintf(w, "{ \"authentication-status-code\" : "+strconv.Itoa(statusCode)+",")
				fmt.Fprintf(w, "\"authentication-error\" : \""+err+"\" }")
			} else {
				w.Header().Set("Content-Type", "plain/text")
				fmt.Fprintf(w, "Authentication Status Code: "+strconv.Itoa(statusCode))
				fmt.Fprintf(w, "\nAuthentication Error: "+err)
			}

			return
		}

		next(w, r)
	}
	return negroni.HandlerFunc(au)
}

//  NOTE: Andrew found this in https://blog.golang.org/error-handling-and-go
//
// This handler wrapper is derived from IsAuthenticated()
type AuthHandler func(http.ResponseWriter, *http.Request) error

func (fn AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if oauthEnabled {
		statusCode, err := CheckAuthentication(r)
		if statusCode != http.StatusOK {
			ct := r.Header.Get("Content-Type")

			//Handle the different response codes appropriately
			w.WriteHeader(statusCode)

			if strings.Contains(strings.ToLower(ct), "json") {
				w.Header().Set("Content-Type", "application/json; charset=UTF-8")
				fmt.Fprintf(w, "{ \"authentication-status-code\" : "+strconv.Itoa(statusCode)+",")
				fmt.Fprintf(w, "\"authentication-error\" : \""+err+"\" }")
			} else {
				w.Header().Set("Content-Type", "plain/text")
				fmt.Fprintf(w, "Authentication Status Code: "+strconv.Itoa(statusCode))
				fmt.Fprintf(w, "\nAuthentication Error: "+err)
			}

			return
		}
	}

	fn(w, r)
}

func Handler501(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusNotImplemented)
	return nil
}

func GetOauthState() bool {
	return oauthEnabled
}

func SetOauthState(state bool) {
	oauthEnabled = state
}
