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
	GET_TIMEOUT_RETRY = 2000
	GET_TIMEOUT_MAX   = 5
	GET_PRINT_STATUS  = 25
)

func GetClient(url string, contentType string, timeout bool) (response_body []byte, err error) {
	doneProcessing := false
	loopCntr := 0

	for !doneProcessing {
		var ret_err error

		err = nil
		response_body, ret_err = getClient(url, contentType)

		doneProcessing = true
		if ret_err != nil {
			if strings.Index(ret_err.Error(), strconv.Itoa(http.StatusNotFound)) >= 0 {
				log.Println("Not Found response accessing ", url)
				time.Sleep(GET_TIMEOUT_RETRY * time.Millisecond)
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
				time.Sleep(GET_TIMEOUT_RETRY * time.Millisecond)
				doneProcessing = false
			} else {
				err = ret_err
				doneProcessing = true
			}
		}

		loopCntr++
		if timeout {
			if loopCntr > GET_TIMEOUT_MAX {
				doneProcessing = true
			}
		} else if (loopCntr % GET_PRINT_STATUS) == 0 {
			if err != nil {
				fmt.Println("GET: Attempting to access ", url, "; timer: ", loopCntr, "; last error: ", err.Error())
			} else {
				fmt.Println("GET: Attempting to access ", url, "; timer: ", loopCntr)
			}
		}
	}

	return
}

func getClient(url string, contentType string) (body []byte, err error) {
	client := RequestAuthorization()

	req, err := http.NewRequest("GET", strings.TrimSpace(url), nil)
	if len(contentType) > 0 {
		req.Header.Set("Content-Type", strings.TrimSpace(contentType))
	}
	response, err := client.Do(req)
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil || response.StatusCode != http.StatusOK {
		if err == nil {
			err = errors.New("HTTP Code: " + strconv.Itoa(response.StatusCode) + "; HTTP Status:" + response.Status)
			body, _ = ioutil.ReadAll(response.Body)
		}

		return
	}

	body, err = ioutil.ReadAll(response.Body)

	return
}
