# Readme.md
Race Condition (TOCTOU)
# Web Application Security Assessment: Core Banking Concurrency Vulnerability


## Legal Disclaimer

This project and accompanying documentation are intended strictly for educational and authorized security research purposes within controlled lab environments.
No real-world banking infrastructure or unauthorized systems were targeted. All sensitive data, IP addresses, session tokens, and identifiers have been sanitized or redacted.
The content is provided to demonstrate secure coding weaknesses, race condition exploitation mechanics, and defensive remediation strategies for application security learning purposes only.


## Executive Summary
[cite_start]A critical **Time-of-Check to Time-of-Use (TOCTOU) Race Condition** was identified within the funds-transfer and credit-recharge mechanisms of the target application[cite: 3]. [cite_start]The platform fails to process balance validation and account adjustments as an atomic transaction[cite: 4]. [cite_start]By issuing synchronized concurrent requests, an attacker can bypass transaction limits and account balance verifications[cite: 5]. [cite_start]This flaw allows users to generate unbacked credit, manipulate balances, and execute unauthorized transfers[cite: 6].

### Key Metrics & Risk Profile
* [cite_start]**Vulnerability Type:** Concurrent Request Race Condition (TOCTOU) [cite: 8]
* **Severity Rating:** **Critical** | [cite_start]**CVSS 3.1 Score: 9.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H`) [cite: 9]
* [cite_start]**OWASP Top 10 Mapping:** A04:2021-Insecure Design [cite: 10]
* [cite_start]**CWE Mapping:** CWE-367 (Time-of-Check to Time-of-Use) [cite: 11]
* [cite_start]**Remediation Priority:** Immediate (Within 24 Hours) [cite: 12]

---

## 1. Risk Defense & Severity Justification

### CVSS 3.1 Rationale
* [cite_start]**Attack Complexity (Low):** Standard HTTP/1.1 last-byte synchronization and HTTP/2 single-packet multiplexing eliminate network jitter, making execution highly reliable[cite: 15].
* [cite_start]**Scope:** Exploiting this flaw changes the state of independent backend account ledgers, breaching the trust boundary between individual account components and the central database[cite: 16].
* [cite_start]**Integrity Impact (High):** Attackers can bypass fundamental financial logic to alter balance states arbitrarily[cite: 17].

### Business & Financial Impact

| Impact Vector | Operational Exposure | Risk Detail |
| :--- | :--- | :--- |
| **Financial Fraud** | Severe-High | [cite_start]Allows extraction of unbacked funds via downstream transfers or cash-outs[cite: 19]. |
| **Ledger Reconciliation** | Medium-High | [cite_start]Out-of-order writes create severe imbalances between recorded balances and actual cash flow[cite: 19]. |
| **Compliance Compliance** | Critical Violation | [cite_start]Non-compliance with PCI-DSS v4.0 (Requirement 6.5) and SOX Section 404 internal control mandates[cite: 19]. |

---

## 2. Technical Breakdown & Root Cause
[cite_start]The vulnerability starts from a non-atomic transactional workflow[cite: 21]. [cite_start]The application processes transfers using sequential, isolated logic loops rather than thread-safe blocks[cite: 21]:
Thread 1 (Request 1): Validate Balance ($50) ---> [Valid] -------------------------> Deduct $50 -> Commit
Thread 2 (Request 2): Validate Balance ($50) ---> [Valid] ---> Deduct $50 -> Commit

Because these actions run across multiple threads simultaneously, overlapping requests pass the validation stage before the first balance deduction commits to the ledger[cite: 24].

### Architectural Flaw Analysis

![TOCTOU Race Condition Workflow](images/architecture_diagram.png)
* **Figure 1:** Diagram explaining the vulnerability window vs a secured atomic transaction flow[cite: 72].

### Why the Flaw Evaded Detection
* **SDLC Deficiencies:** The current pipeline lacks thread-concurrency testing within the QA automated suite[cite: 26].
* **Tooling Limitations:** Standard Static Analysis (SAST) engines struggle to trace multi-threaded data contexts at runtime, while typical Dynamic Analysis (DAST) tools scan endpoints sequentially rather than in parallel[cite: 27].
* **Architectural Gaps:** The design review process failed to mandate row-level locking or distributed token locks for multi-threaded transactional logic[cite: 28].

---

## 3. Vulnerability Evidence & Payloads

### Scenario A: Phone Credit Transfer Subversion
An authenticated user captured a standard $5.50 credit recharge request[cite: 31]. By duplicating this request into a parallel group and executing them simultaneously, the application processed overlapping validation steps[cite: 32]. This bypassed balance restrictions, inflating the credit to $578.46[cite: 33].

http
POST /dashboard/transfer?_data=routes%2Fdashboard.transfer HTTP/1.1
Host: 10.128.XXX.XX:8080
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Cookie: _session=eyJ1c2VySWQiOiI3MTEzMzc...

targetPhoneNumber=07113371111&confirmTargetPhoneNumber=07113371111&amount=5.5
http'''

Validation of the attack structure using Burp Suite Repeater tab group containing requests synchronized for parallel execution.  
Proof of impact displaying the resulting application dashboard state with an artificially inflated balance of $578.46 alongside the proof-of-concept flag.

Scenario B: Multi-Account Ledger Attack
The core banking utility (/transfer/6282) was targeted with concurrent multipart form-data requests.

POST /transfer/6282 HTTP/1.1
Host: 10.129.XXX.XXX:5000
Content-Type: multipart/form-data; boundary=---SynchBoundary
Cookie: session=e2N0b3...

---SynchBoundary
Content-Disposition: form-data; name="fund_being_transferred"
210
---SynchBoundary

The server generated concurrent write errors (HTTP 500) and successful transfers simultaneously. This bypassed validation logic and inflated the account balance to $4,095.75, exceeding the system's $1,000 threshold limit.  Figure 4: Telemetry showing a successful transaction ({"result":true}) inside the parallel attack window despite insufficient baseline capital. 

Figure 5: Sequential execution trace where a post-race loop check correctly rejects the transaction execution path ({"result":false}).

Figure 6: Database thread exhaustion and write locks collapsing under concurrent stress, resulting in a 500 Internal Server Error. 

Figure 7: Final validation screen displaying the backend bank ledger reflecting the subverted balance of $4,095.75 USD for user Zavodni Stav.  4. Remediation ArchitectureTo permanently resolve this issue, the transaction workflow must be refactored into a single, atomic database block using Pessimistic Locking.  


-- 1. Lock the specific user account row during verification
SELECT balance FROM accounts WHERE account_id = 6282 FOR UPDATE;

-- 2. Validate funds within application logic 
-- 3. Execute ledger adjustments inside an ACID transaction block
UPDATE accounts SET balance = balance - 210 WHERE account_id = 6282;
UPDATE accounts SET balance = balance + 210 WHERE account_id = 4621;

-- 4. Commit changes and release the row lock
COMMIT;


Alternative Controls

Database Constraints:
Add an unsigned check constraint (ALTER TABLE accounts ADD CONSTRAINT chk_balance CHECK (balance >= 0);) to reject negative balances at the engine level.
Distributed Locking: For microservices, use Redis-backed distributed locks tied to the unique User ID to enforce single-thread request execution.


Detection & Monitoring Recommendations

SIEM Detection Rules
High-Frequency Thresholds: Alert when a single authenticated session ID generates more than 10 state-changing requests (POST / PUT) to transaction endpoints within a 100-millisecond window. 
Database Anomalies: Monitor for sudden spikes in database deadlock exceptions or serialization failures (SQLSTATE 40001). 

Fraud Mitigation 

Micro-Reconciliation Daemons: Deploy background processes to continuously reconcile account balances (Starting Balance + Interventions - Outflow).
Flag and freeze any account showing a ledger mismatch.  
