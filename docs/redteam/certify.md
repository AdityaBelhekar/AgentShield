# AgentShield Certify

## Certification Command

Generate certification artifacts from a red-team report:

```bash
agentshield certify generate reports/redteam.json \
  --output reports/certification.json \
  --badge reports/agentshield-badge.svg \
  --html reports/certification.html
```

## What the Badge Means

A certification badge indicates the agent has been evaluated against the bundled adversarial scenario set and achieved the required detection standard for issuance.

## Add Badge to Your README

Place the generated SVG in your repository (for example `assets/agentshield-badge.svg`) and include the following markdown:

```markdown
[![AgentShield Certified](assets/agentshield-badge.svg)](https://github.com/AdityaBelhekar/AgentShield)
```

You can link the badge to your own certification report artifact for traceability.