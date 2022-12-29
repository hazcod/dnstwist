package dnstwist

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	dnstwistURL = "https://dnstwist.it"
	scanURI     = "/api/scans"
)

var (
	httpClient = http.Client{Timeout: time.Second * 10}
)

type dnsTwistRequest struct {
	URL string `json:"url"`
}

type dnsTwistResponse struct {
	Complete   int    `json:"complete"`
	ID         string `json:"id"`
	Registered int    `json:"registered"`
	Remaining  int    `json:"remaining"`
	Timestamp  int    `json:"timestamp"`
	Total      int    `json:"total"`
	URL        string `json:"url"`
}

// TODO: replace dnstwist by our own permutation engine

func Request(ctx context.Context, l *logrus.Logger, domain string) (*Twister, error) {
	if domain == "" || !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	logger := l.WithField("domain", domain)

	payload := dnsTwistRequest{
		URL: domain,
	}

	bodyBytes, err := json.Marshal(&payload)
	if err != nil {
		return nil, fmt.Errorf("could not encode body: %v", err)
	}

	url := dnstwistURL + scanURI
	if logger.Logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithField("body", string(bodyBytes)).WithField("url", url).
			Debug("sending request")
	}

	httpRequest, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("could not create http request: %v", err)
	}

	httpRequest.Header.Set("content-type", "application/json")

	resp, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("could not execute http request: %v", err)
	}

	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %v", err)
	}

	if resp.StatusCode > 399 {
		if logger.Logger.IsLevelEnabled(logrus.DebugLevel) {
			logger.Debugf("%s", string(respBytes))
		}
		return nil, fmt.Errorf("response returned status code %d", resp.StatusCode)
	}

	var response dnsTwistResponse
	if err := json.Unmarshal(respBytes, &response); err != nil {
		return nil, fmt.Errorf("could not decode response: %v", err)
	}

	if response.ID == "" {
		return nil, fmt.Errorf("empty domain id returned for %s", domain)
	}

	twist := Twister{id: response.ID, ctx: ctx, logger: logger}

	return &twist, nil
}
