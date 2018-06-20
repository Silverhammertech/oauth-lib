package oauth_lib

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2/jws"
	"time"
)

const (
	maxAcceptableClockSkewSeconds = int64(60)
	debugCurrent                  = false
)

var oauthKeyCache map[string]string

type ClaimSet struct {
	Iss   string   `json:"iss"`             // email address of the client_id of the application making the access token request
	Scope []string `json:"scope,omitempty"` // space-delimited list of the permissions the application requests
	Aud   []string `json:"aud"`             // descriptor of the intended target of the assertion (Optional).
	Exp   int64    `json:"exp"`             // the expiration time of the assertion (seconds since Unix epoch)
	Iat   int64    `json:"iat"`             // the time the assertion was issued (seconds since Unix epoch)
	Typ   string   `json:"typ,omitempty"`   // token type (Optional).

	// Email for which the application is requesting delegated access (Optional).
	Sub string `json:"sub,omitempty"`

	// The old name of Sub. Client keeps setting Prn to be
	// complaint with legacy OAuth 2.0 providers. (Optional)
	Prn string `json:"prn,omitempty"`

	// See http://tools.ietf.org/html/draft-jones-json-web-token-10#section-4.3
	// This array is marshalled using custom code (see (c *ClaimSet) encode()).
	PrivateClaims map[string]interface{} `json:"-"`
}

type jsonPublicKey struct {
	Algorithm string `json:"alg"`
	Value     string `json:"value"`
	Kty       string `json:"kty"`
	Use       string `json:"use"`
	N         string `json:"n"`
	E         string `json:"e"`
}

func decode(token string) (claims ClaimSet, err error) {

	s := strings.Split(token, ".")
	if len(s) < 2 {
		err = errors.New("FastToken.decode(): invalid token received")
		return
	}

	// add back missing padding
	t := s[1]
	switch len(t) % 4 {
	case 1:
		t += "==="
	case 2:
		t += "=="
	case 3:
		t += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(t)
	if DEBUG {
		fmt.Println("DBG-> decoded: ", string(decoded))
	}
	if err != nil {
		return
	}

	err = json.NewDecoder(bytes.NewBuffer(decoded)).Decode(&claims)
	if err != nil {
		//  not a valid token
		if DEBUG {
			fmt.Println("DBG-> not a valid token; err: ", err.Error())
			fmt.Println("DBG-> tkn: ", token)
		}
		return
	}

	return
}

func getKey(keyURL string) (alg, val string) {
	var public_key jsonPublicKey

	//  check the cache to see if URL already there
	body, present := oauthKeyCache[keyURL]
	if !present {

		if DEBUG {
			fmt.Println("DBG.getKey()-> requesting public key from uaa server")
		}

		//  go get key
		resp, err := http.Get(keyURL)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil || resp.StatusCode != 200 {
			if err != nil {
				log.Println("Error reading from ", keyURL, "; err: ", err.Error())
			} else {
				log.Println("Error reading from ", keyURL, "; StatusCode: ", resp.StatusCode)
			}

			return
		}

		//  get key from response
		rval, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1048576))
		body = string(rval)
		if err != nil {
			log.Println("Error: Unable to read Public Key from ", keyURL)
			return
		}

		oauthKeyCache[keyURL] = body
	}

	if DEBUG {
		fmt.Println("DBG.getKey()-> body: ", string(body))
	}
	err := json.Unmarshal([]byte(body), &public_key)
	if err != nil {
		log.Println("Error: Unable to decode Public Key from ", keyURL)
		return
	}

	//  save to cache
	val = public_key.Value
	alg = public_key.Algorithm

	return
}

func scanList(key string, list []string) (present bool) {
	present = false

	for i := range list {
		//		if DEBUG { fmt.Println("DBG-> list[i]: ", list[i], "; key: ", key) }
		if key == list[i] {
			present = true
			break
		}
	}

	return
}

func getPredixZones(list []string) (zones []string) {

	for i := range list {
		//		if DEBUG { fmt.Println("DBG-> list[i]: ", list[i]) }
		if strings.HasPrefix(list[i], "predix-acs.zones.") && strings.HasSuffix(list[i], ".user") {
			zones = append(zones, list[i])
		}
	}

	return
}

func ValidateClaimSet(claims ClaimSet) (valid bool) {
	valid = false

	// verify exp, iat, aud
	iatDate := (claims.Iat - maxAcceptableClockSkewSeconds)
	expDate := (claims.Exp + maxAcceptableClockSkewSeconds)
	current := time.Now().Unix()

	if DEBUG {
		fmt.Println("DBG.ValidateClaimSet()-> iat: ", iatDate, "; current: ", current, "; exp: ", expDate)
	}
	if iatDate > current {
		if DEBUG {
			fmt.Println("DBG-> token timestamp is before issue date")
			fmt.Println("DBG.ValidateClaimSet()-> iat: ", iatDate, "; current: ", current, "; exp: ", expDate)
		}
		return
	} else if expDate <= current {
		if DEBUG {
			fmt.Println("DBG-> token timestamp is expired")
			fmt.Println("DBG.ValidateClaimSet()-> iat: ", iatDate, "; current: ", current, "; exp: ", expDate)
		}
		return
	}

	//  need to verify scopes here?
	scopes := claims.Scope
	if (scopes != nil) && (len(scopes) > 0) && (CLIENT_ZONE != "") {
		if DEBUG {
			fmt.Println("DBG.ValidateClaimSet()-> scope: ", scopes)
		}

		vscope := false
		zones := getPredixZones(claims.Scope)
		if len(zones) > 1 {
			for i := range zones {
				if CLIENT_ZONE == zones[i] {
					vscope = true
				}
			}
		} else if len(zones) == 1 {
			if CLIENT_ZONE == zones[0] {
				vscope = true
			}
		}

		if !vscope {
			if CURRENT_DEBUG {
				fmt.Println("DBG.ValidateClaimSet()-> This token does not have the correct zone")
				fmt.Println("DBG.ValidateClaimSet()-> our scope: ", CLIENT_ZONE, "; token scope: ", zones)
			}
			//return
		}
	}

	//  need to verify audience here?
	audience := claims.Aud
	if (audience != nil) && (len(audience) > 0) {
		present := scanList(CLIENT_ID, audience)
		if !present {
			if CURRENT_DEBUG {
				fmt.Println("DBG.ValidateClaimSet()-> This service is not in the AUD List")
				fmt.Println("DBG.ValidateClaimSet()-> aud: ", audience)
				fmt.Println("DBG.ValidateClaimSet()-> client_id: ", CLIENT_ID)
			}
			return
		}
	}

	valid = true

	return
}

func FastTokenVerify(token string) (valid bool) {
	valid = false

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		log.Println("DBG-> not a valid token")
		fmt.Println("DBG-> tkn: ", token)
		return
	}

	//  decode JWT token
	claims, err := decode(token)
	if err != nil {
		//  not a valid token
		if DEBUG {
			log.Println("DBG-> not a valid token; err: ", err.Error())
			fmt.Println("DBG-> tkn: ", token)
		}
		return
	}

	if DEBUG {
		fmt.Println("DBG-> claims: ", claims)
		fmt.Println("DBG-> claims.iss: ", claims.Iss)
	}

	//  check if the token is from a trusted issuer
	issuer := strings.TrimSuffix(claims.Iss, "/oauth/token")
	if DEBUG {
		fmt.Println("DBG-> issuer: ", issuer)
	}
	if issuer == uaaHostName {
		//
		uaa_url := issuer + "/token_key"
		_, public_key := getKey(uaa_url)
		if DEBUG {
			fmt.Println("DBG-> public_key: ", public_key)
		}

		key, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(public_key))

		err = jws.Verify(token, key)
		if err != nil {
			if DEBUG {
				fmt.Println("DBG.FastTokenVerify()-> jws.Verify() returned error: ", err.Error())
			}
		}

		valid = ValidateClaimSet(claims)
	}

	return
}
