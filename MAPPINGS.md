# How AER relates to regulation and security frameworks

This document is informative. It is not legal advice, and using AER does not by itself make a system compliant with anything. It shows which parts of a logging obligation the format can carry, and which parts remain with the system and the organisation that runs it.

## EU Artificial Intelligence Act, Regulation (EU) 2024/1689

Article 12 applies to high-risk AI systems. Under Article 113 as currently amended, the high-risk requirements apply from 2 December 2027 for Annex III systems and from 2 August 2028 for Annex I systems. Check the current consolidated text on EUR-Lex before relying on a date.

| Provision | What it asks for, in summary | What AER contributes | What AER does not do |
|---|---|---|---|
| Article 12(1) | High-risk systems must technically allow events to be recorded automatically over their lifetime | A record format and a writer that appends one record per decision | Decide which events the system has to log |
| Article 12(2)(a) | Logging must support identifying situations that may present a risk or lead to a substantial modification | `decision.verdict`, `decision.reason`, `decision.policy.version` and `event.type: system` records for policy and configuration changes | Assess whether a situation is a risk within the meaning of Article 79(1) |
| Article 12(2)(b) | Logging must support post-market monitoring under Article 72 | An exportable, verifiable history that a monitoring process can analyse | Provide the monitoring plan or the analysis |
| Article 12(2)(c) | Logging must support monitoring of operation by deployers under Article 26(5) | Per-decision records with `actor`, `event` and `correlation_id` | Provide the deployer's monitoring process |
| Article 12(3) | For remote biometric identification systems: period of use, reference database, matching input data, and who verified the result | These can be carried in `timestamp`, `event.source`, `event.content_digest` and `ext` | Define them. AER has no biometric-specific members |
| Article 19 | Providers keep automatically generated logs under their control for a period appropriate to the purpose, and at least six months | A format that can be retained and later verified | Set or enforce a retention period |
| Article 26(6) | Deployers keep the logs under their control for at least six months | As above | As above |

The Act says what must be loggable and for how long logs are kept. It does not say how a log is shown to be complete and unaltered when it is produced to an authority. That evidential question is the one AER addresses.

## MITRE ATLAS

| Item | Relation |
|---|---|
| AML.M0024, AI Telemetry Logging | AER is a concrete format for the telemetry this mitigation calls for, with integrity protection added |
| AML.T0051, LLM Prompt Injection | `event.type` of `input` or `context` with a `block` verdict records a detected attempt |
| AML.T0053, AI Agent Tool Invocation | `event.type: tool_call` with `scope.requested` and `scope.granted` records what an agent tried to do and what it was allowed to do |
| AML.T0086, Exfiltration via AI Agent Tool Invocation | The same record, with the destination captured in the scope string or in `ext` |
| AML.T0080, AI Agent Context Poisoning | `event.type: memory_write` records attempts to persist content |

Technique and mitigation identifiers follow ATLAS v5.6.0.

## NIST AI Risk Management Framework

The framework's Measure and Manage functions depend on being able to observe what a deployed system did and to reconstruct incidents. AER provides a record that can serve as that evidence. It does not implement any function of the framework.

## What stays with you

- Deciding which events are logged, and making sure no path through the system skips the writer.
- Custody of HMAC keys and checkpoint signing keys.
- Where checkpoints are kept, and who can reach them.
- Retention, deletion and access control.
- Whether what the records say is true.
