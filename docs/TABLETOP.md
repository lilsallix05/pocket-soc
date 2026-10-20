# Clinic file-transfer tabletop

This is a facilitator package with synthetic events. No real clinic or participant session is asserted. All external IPs in fixtures use documentation networks. All identities are fictional.

**Roles:** incident commander, technical analyst, DPO/notification owner, business owner and scribe. **Materials:** one local browser, the included JSONL files, an incident record and the English/Malay runbook.

1. Open a practice record. The first inject describes a 2.4 MB upload from `10.20.0.12` to `203.0.113.70`. Ask what evidence supports a breach versus routine traffic; link the observation hash.
2. Reveal 240 affected patients with medical information. Record the four qualitative harm criteria and affected count. Show why a count below 1,001 does not settle the decision.
3. Reveal a processor's earlier observation. Record occurrence separately, explain the selected planning-clock basis and assign a reviewer. Do not fabricate a notification date to make a clock look green.
4. Draft the notice fields, label unknown facts and identify approval/confirmation owners. Discuss the current official form, confirmation receipt, individual notices and phased updates. Send nothing during the exercise.
5. Record containment/recovery decisions and lessons. Try allowlisting the mock backup at `198.51.100.10`, then examine suppressed observations. Discuss why suppressing the incident destination could conceal activity.

Record actual participants, start/end times, decision evidence, acknowledgement latency and improvement owners after a human session. Leave these unknown until it occurs.

# Two-minute guided demonstration (script, not a recorded video)

- 0:00–0:20: Start practice. Identify the clock basis and practice label.
- 0:20–0:45: In Decision record, enter 240 people and sensitive data = Yes. Save and explain the two notification recommendations.
- 0:45–1:05: Add an evidence note and mark a response action; show the hash-linked timeline.
- 1:05–1:30: Open telemetry, save the fixture backup allowlist, inspect the 30 suppressed records and export the report.
- 1:30–1:50: Save notification preparation, discuss the missing confirmation reference and export the complete record.
- 1:50–2:00: Open the runbook, point to the Malay version in `docs/RUNBOOK-MS.md`, the deployment prerequisites and the fixture-only timing.
