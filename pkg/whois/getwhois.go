package whois

import (
	"fmt"
	"github.com/hazcod/dnstwist/pkg/dnstwist"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/idna"
	"strings"
	"time"
)

const (
	maxWhoisTries = 5
	ianaWhois     = "whois.iana.org"
)

func getTopDomain(domain string) string {
	parts := strings.Split(domain, ".")

	if len(parts) < 3 {
		return domain
	}

	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func Get(l *logrus.Entry, result dnstwist.Result, cutoffDate time.Time) (map[string]interface{}, bool, error) {
	logger := l.WithField("domain", result.Domain).WithField("cutoff_date", cutoffDate.Format(time.RFC1123Z))

	asciiDomain, err := idna.ToASCII(result.Domain)
	if err != nil {
		logger.WithError(err).Warn("could not convert domain to ascii")
		asciiDomain = result.Domain
	}

	whoisRaw := ""

	for i := 0; i < maxWhoisTries; i++ {
		logger.WithField("attempt", fmt.Sprintf("%d/%d", i+1, maxWhoisTries)).Debug("retrieving whois")

		whoisRaw, err = whois.Whois(getTopDomain(asciiDomain), ianaWhois)
		if err != nil {
			logger.WithError(err).Debug("could not retrieve whois")
			continue
		}

		break
	}

	expires := ""
	created := ""
	updated := ""
	abuseContact := ""
	isSuspicious := false

	if whoisRaw != "" {
		whoisResult, err := whoisparser.Parse(whoisRaw)
		if err != nil {
			logger.WithError(err).WithField("whois_raw", whoisRaw).Warn("could not parse whois")
			return nil, false, fmt.Errorf("could not parse whois: %v", err)
		}

		if whoisResult.Domain.ExpirationDateInTime != nil {
			expires = whoisResult.Domain.ExpirationDateInTime.Format(time.RFC1123Z)

			if whoisResult.Domain.ExpirationDateInTime.Before(time.Now()) {
				logger.Debug("suspicious; domain expiration is before today")
				isSuspicious = true
			}
		}
		if whoisResult.Domain.CreatedDateInTime != nil {
			created = whoisResult.Domain.CreatedDateInTime.Format(time.RFC1123Z)

			if whoisResult.Domain.CreatedDateInTime.After(cutoffDate) {
				logger.Debug("suspicious; domain recently created")
				isSuspicious = true
			}
		}
		if whoisResult.Domain.UpdatedDateInTime != nil {
			updated = whoisResult.Domain.UpdatedDateInTime.Format(time.RFC1123Z)

			if whoisResult.Domain.UpdatedDateInTime.After(cutoffDate) {
				logger.Debug("suspicious; domain recently updated")
				isSuspicious = true
			}
		}

		if whoisResult.Registrar != nil {
			abuseContact = whoisResult.Registrar.Email
		}
	}

	return map[string]interface{}{
		"suspicious": isSuspicious,
		"geo":        result.Geoip,
		"a_records":  fmt.Sprintf("%s", result.DNSA),
		"expires":    expires,
		"created":    created,
		"updated":    updated,
		"abuse":      abuseContact,
	}, isSuspicious, nil
}
