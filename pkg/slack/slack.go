package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

const (
	typeSection  = "section"
	typeMarkdown = "mrkdwn"
)

type webhookBlock struct {
	Type string `json:"type"`
	Text struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"text"`
}

type webhookMessage struct {
	Blocks []webhookBlock `json:"blocks"`
}

func Post(l *logrus.Logger, webhook string, domains map[string]map[string]interface{}) error {
	for domain, fields := range domains {

		domLogger := l.WithField("domain", domain)
		domLogger.Debug("sending Slack messsage")

		whMessage := webhookMessage{}

		whMessage.Blocks = append(whMessage.Blocks, webhookBlock{
			Type: typeSection,
			Text: struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{
				Type: typeMarkdown,
				Text: "*Suspicious domain detected:* " + domain + "\n",
			},
		})

		properties := ""
		for k, v := range fields {
			properties += fmt.Sprintf("%s: %s\n", k, v)
		}

		whMessage.Blocks = append(whMessage.Blocks, webhookBlock{
			Type: typeSection,
			Text: struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{
				Type: typeMarkdown,
				Text: properties,
			},
		})

		reqBytes, err := json.Marshal(&whMessage)
		if err != nil {
			return fmt.Errorf("could not encode to json: %v", err)
		}

		httpClient := http.Client{Timeout: time.Second * 5}

		httpRequest, err := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(reqBytes))
		if err != nil {
			return fmt.Errorf("could not create HTTP request: %v", err)
		}

		httpRequest.Header.Set("content-type", "application/json")

		resp, err := httpClient.Do(httpRequest)
		if err != nil || resp.StatusCode > 399 {
			return fmt.Errorf("could not send Slack message (status code %d): %v", resp.StatusCode, err)
		}

	}

	l.WithField("total", len(domains)).Info("sent Slack messages")

	return nil
}
