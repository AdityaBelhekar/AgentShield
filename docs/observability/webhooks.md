# Slack & PagerDuty

AgentShield ships webhook notifiers for Slack and PagerDuty with severity thresholds, cooldown controls, and retry behavior.

## Slack

- Config model: `WebhookConfig`
- Required when enabled: `slack_webhook_url`
- Minimum severity gate: `slack_min_severity`
- Cooldown: `slack_cooldown_seconds`

## PagerDuty

- Config model: `WebhookConfig`
- Required when enabled: `pagerduty_routing_key` (32 chars)
- Minimum severity gate: `pagerduty_min_severity`
- Cooldown: `pagerduty_cooldown_seconds`
- Endpoint: PagerDuty Events API v2

## Example

```python
from agentshield.notifications import WebhookConfig, WebhookNotifier

config = WebhookConfig(
    slack_enabled=True,
    slack_webhook_url="https://hooks.slack.com/services/XXX/YYY/ZZZ",
    slack_min_severity="HIGH",
    pagerduty_enabled=True,
    pagerduty_routing_key="0123456789abcdef0123456789abcdef",
    pagerduty_min_severity="CRITICAL",
)

notifier = WebhookNotifier(
    webhook_config=config,
    redis_url="redis://localhost:6379",
)
```

## Alerting Behavior

- Canary-triggered events bypass normal severity thresholds and are treated as urgent.
- Retry strategy uses bounded attempts to avoid runaway notification storms.
- Rate limiting is keyed per agent and threat family.