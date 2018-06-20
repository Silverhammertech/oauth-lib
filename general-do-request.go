package oauth_lib

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	HTTP_REQUEST_TIMEOUT_RETRY = 2000
	HTTP_REQUEST_TIMEOUT_MAX   = 5
	HTTP_PRINT_STATUS          = 25
)

func DoRequest(req *http.Request, timeout bool) (response *http.Response, err error) {
	doneProcessing := false
	loopCntr := 0

	for !doneProcessing {
		client := RequestAuthorization()
		response, err = client.Do(req)

		doneProcessing = true

		switch {
		case err != nil:
			doneProcessing = true
		case response == nil:
			if err == nil { // init error in case nil
				err = errors.New("No Response/response body from request")
			}
			doneProcessing = true

		case response.StatusCode == http.StatusNotFound: // 404
			log.Println("Not Found response accessing ", req.Host+req.URL.Path)
			time.Sleep(HTTP_REQUEST_TIMEOUT_RETRY * time.Millisecond)
			doneProcessing = false
		case response.StatusCode == http.StatusNotImplemented: // 501
			doneProcessing = true
		case response.StatusCode == http.StatusBadRequest: // 400
			doneProcessing = true
		case response.StatusCode == http.StatusInternalServerError: // 500
			log.Println("Internal Server Error response accessing ", req.Host+req.URL.Path)
			time.Sleep(HTTP_REQUEST_TIMEOUT_RETRY * time.Millisecond)
			doneProcessing = false
		default: // for everything else
			doneProcessing = true
		}

		loopCntr++
		if timeout {
			if loopCntr > HTTP_REQUEST_TIMEOUT_MAX {
				doneProcessing = true
			}
		} else if (loopCntr % HTTP_PRINT_STATUS) == 0 {
			if err != nil {
				fmt.Println(req.Method, ": Attempting to access ", req.URL.String(), "; timer: ", loopCntr, "; last error: ", err.Error())
			} else {
				fmt.Println(req.Method, ": Attempting to access ", req.URL.String(), "; timer: ", loopCntr)
			}
		}
	}

	return
}
