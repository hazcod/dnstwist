package dnstwist

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
)

type Result struct {
	DNSA    []string `json:"dns_a,omitempty"`
	DNSMx   []string `json:"dns_mx,omitempty"`
	DNSNs   []string `json:"dns_ns,omitempty"`
	Domain  string   `json:"domain"`
	Fuzzer  string   `json:"fuzzer"`
	Geoip   string   `json:"geoip,omitempty"`
	DNSAaaa []string `json:"dns_aaaa,omitempty"`
}

func (t *Twister) GetResult() ([]Result, error) {
	if t.id == "" {
		return nil, errors.New("id is nil, cannot retrieve domains")
	}

	url := dnstwistURL + scanURI + "/" + t.id + "/domains"

	if t.logger.Logger.IsLevelEnabled(logrus.DebugLevel) {
		t.logger.WithField("url", url).Debug("sending request")
	}

	httpRequest, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create http request: %v", err)
	}

	resp, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("could not execute http request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		return nil, fmt.Errorf("response returned status code %d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %v", err)
	}

	var response []Result
	if err := json.Unmarshal(respBytes, &response); err != nil {
		return nil, fmt.Errorf("could not decode response: %v", err)
	}

	return response, nil
}
