# dnstwist

This is a tool that will fetch potential typosquat domains which could be targeting your domain.
It will take into account the registration and/or

## Usage

First create a configuration file:
```yaml
# log settings, optional
log:
  # log level to use
  level: info

# the domains you'd like to monitor, required
domains:
  # domain(s) to monitor
  watchlist: [domain.com]
  # any domains to ignore
  whitelist: []
  # domains created in the last week
  created_since: 168h

# send alerts to a Slack channel, optional
slack:
  # slack channel webhook
  webhook: https://hooks.slack.com/services/XXX
```

And then run the tool:
```shell
% dnstwist -config=config.yml
```

You can also set configuration values via environment variables:

```shell
% LOG_LEVEL=info DOMAIN_WATCHLIST=domain.com SLACK_WEBHOOK=xxx dnstwist
```