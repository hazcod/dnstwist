package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/hazcod/dnstwist/config"
	"github.com/hazcod/dnstwist/pkg/dnstwist"
	"github.com/hazcod/dnstwist/pkg/slack"
	"github.com/hazcod/dnstwist/pkg/whois"
	"github.com/sirupsen/logrus"
	"time"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	ctx := context.Background()

	confFile := flag.String("config", "", "The YAML configuration file.")
	flag.Parse()

	conf := config.Config{}
	if err := conf.Load(*confFile); err != nil {
		logger.WithError(err).WithField("config", *confFile).Fatal("failed to load configuration")
	}

	if err := conf.Validate(); err != nil {
		logger.WithError(err).WithField("config", *confFile).Fatal("invalid configuration")
	}

	logrusLevel, err := logrus.ParseLevel(conf.Log.Level)
	if err != nil {
		logger.WithError(err).Error("invalid log level provided")
		logrusLevel = logrus.InfoLevel
	}
	logger.SetLevel(logrusLevel)

	now := time.Now()
	cutoffDate := time.Time{}
	if conf.Domains.CreatedSince != "" {
		duration, err := time.ParseDuration(conf.Domains.CreatedSince)
		if err != nil {
			logger.WithError(err).WithField("duration", conf.Domains.CreatedSince).
				Fatal("invalid created_since provided")
		}

		cutoffDate = now.Add(-1 * duration)
	}

	totalDomains := len(conf.Domains.WatchList)
	suspiciousDomains := make(map[string]map[string]interface{})

	logger.WithField("domains", totalDomains).Info("starting monitoring")

	for i, domain := range conf.Domains.WatchList {
		domainLogger := logger.WithField("domain", domain)
		domainLogger.WithField("progress", fmt.Sprintf("%d/%d", i+1, totalDomains)).Info("monitoring domain")

		twister, err := dnstwist.Request(ctx, logger, domain)
		if err != nil {
			domainLogger.WithError(err).Error("could not request domain check")
			continue
		}

		if err := twister.Wait(); err != nil {
			domainLogger.WithError(err).Error("error during domain check")
			continue
		}

		results, err := twister.GetResult()
		if err != nil {
			domainLogger.WithError(err).Error("could not retrieve domain result")
			continue
		}

		domainLogger.WithField("results", len(results)).Info("enumerated potential attack domains")
		for _, attackDomain := range results {
			attackLogger := domainLogger.WithField("attack_domain", attackDomain.Domain)

			whoisResult, suspicious, err := whois.Get(attackLogger, attackDomain, cutoffDate)
			if err != nil {
				attackLogger.WithError(err).Warn("could not retrieve whois")
			}

			domainLogger.WithFields(whoisResult).Info(attackDomain.Domain)

			if suspicious {
				suspiciousDomains[attackDomain.Domain] = whoisResult
			}
		}
	}

	logger.WithField("suspicious_domains", len(suspiciousDomains)).Info("concluded suspicious domains")

	if conf.Slack.Webhook != "" {
		logger.Debug("reporting suspicious domain")

		delete(suspiciousDomains, "suspicious")

		if err := slack.Post(logger, conf.Slack.Webhook, suspiciousDomains); err != nil {
			logger.WithError(err).Error("could not report domain to Slack")
		}

		logger.Debug("sent slack messages")
	}

	logger.Info("finished")
}
