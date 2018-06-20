package oauth_lib

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	POST_TIMEOUT_RETRY = 2000
	POST_TIMEOUT_MAX   = 5
	POST_PRINT_STATUS  = 25
)

func PostClient(url string, body []byte, timeout bool) (response_body []byte, err error) {
	doneProcessing := false
	loopCntr := 0

	for !doneProcessing {
		var ret_err error

		err = nil
		response_body, ret_err = postClient(url, body)

		doneProcessing = true
		if ret_err != nil {
			if strings.Index(ret_err.Error(), strconv.Itoa(http.StatusNotFound)) >= 0 {
				log.Println("Not Found response accessing ", url)
				time.Sleep(POST_TIMEOUT_RETRY * time.Millisecond)
				doneProcessing = false
			} else if strings.Index(ret_err.Error(), strconv.Itoa(http.StatusNotImplemented)) >= 0 {
				err = ret_err
				doneProcessing = true
			} else if strings.Index(ret_err.Error(), strconv.Itoa(http.StatusBadRequest)) >= 0 {
				err = ret_err
				doneProcessing = true
			} else if strings.Index(ret_err.Error(), strconv.Itoa(http.StatusNoContent)) >= 0 {
				err = ret_err
				doneProcessing = true
			} else if strings.Index(ret_err.Error(), strconv.Itoa(http.StatusInternalServerError)) >= 0 {
				log.Println("Internal Server Error response accessing ", url)
				time.Sleep(POST_TIMEOUT_RETRY * time.Millisecond)
				doneProcessing = false
			} else {
				err = ret_err
				doneProcessing = true
			}
		}

		loopCntr++
		if timeout {
			if loopCntr > POST_TIMEOUT_MAX {
				doneProcessing = true
			}
		} else if (loopCntr % POST_PRINT_STATUS) == 0 {
			if err != nil {
				fmt.Println("POST: Attempting to access ", url, "; timer: ", loopCntr, "; last error: ", err.Error())
			} else {
				fmt.Println("POST: Attempting to access ", url, "; timer: ", loopCntr)
			}
		}
	}

	return
}

func postClient(url string, body []byte) (response_body []byte, err error) {
	client := RequestAuthorization()
	response, err := client.Post(url, "application/json", strings.NewReader(string(body)))
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil || ((response.StatusCode != http.StatusOK) && (response.StatusCode != http.StatusCreated)) {
		if err == nil {
			err = errors.New("HTTP Code: " + strconv.Itoa(response.StatusCode) + "; HTTP Status:" + response.Status)
		}

	} else {
		response_body, err = ioutil.ReadAll(response.Body)
	}

	return
}
