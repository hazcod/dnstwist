package dnstwist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	maxWait  = time.Minute * 10
	pollTime = time.Second * 3
)

type Twister struct {
	id     string
	ctx    context.Context
	logger *logrus.Entry
}

func (t *Twister) getRemainingDomains() (uint, error) {
	if t.id == "" {
		return 0, errors.New("cannot wait on empty id")
	}

	url := dnstwistURL + scanURI + "/" + t.id
	t.logger.WithField("url", url).Debug("sending request")

	httpRequest, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("could not create http request: %v", err)
	}

	resp, err := httpClient.Do(httpRequest)
	if err != nil {
		return 0, fmt.Errorf("could not execute http request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		return 0, fmt.Errorf("response returned status code %d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("could not read response body: %v", err)
	}

	var response dnsTwistResponse
	if err := json.Unmarshal(respBytes, &response); err != nil {
		return 0, fmt.Errorf("could not decode response: %v", err)
	}

	if response.Remaining < 0 {
		return 0, fmt.Errorf("invalid remaining returned: %d", response.Remaining)
	}

	return uint(response.Remaining), nil
}

func waitTimeout(ctx context.Context, wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-ctx.Done():
		return true
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

func (t *Twister) Wait() error {
	var wg sync.WaitGroup

	t.logger.Debug("spawning poll goroutine")

	wg.Add(1)
	go func() {
		for {
			t.logger.Debug("retrieving remaining domains")

			remaining, err := t.getRemainingDomains()
			if err != nil {
				t.logger.WithError(err).Error("could not retrieve remaining domains, retrying")
			}

			if remaining <= 0 {
				t.logger.Debug("finished")
				wg.Done()
				return
			}

			t.logger.WithField("remaining", remaining).Debugf("sleeping %s", pollTime)
			time.Sleep(pollTime)
		}
	}()

	t.logger.Debug("waiting for poller to complete")
	if hasTimedOut := waitTimeout(t.ctx, &wg, maxWait); hasTimedOut {
		return errors.New("timed out waiting for completion")
	}

	t.logger.Debug("poller finished")

	return nil
}
