# SessionGuard: A Lightweight Multi-Signal Framework for Web Session Hijacking Detection

**A.M. Dhivya [1], G. Joel [2], S. Dhivakar [3], Nived V Puthen Purakkal [4]**  
*[1] Assistant Professor, Department of Computer Science and Business Systems, KIT-Kalaignarkarunanidhi Institute of Technology, Coimbatore, India. Email: sithikaseema9@gmail.com*  
*[2][3][4] Students, Department of Computer Science and Business Systems, KIT-Kalaignarkarunanidhi Institute of Technology, Coimbatore, India. Email: kit27.csbs26@gmail.com*

---

### Abstract
Web session hijacking is a significant post-authentication security threat in which an attacker who obtains a valid session token can impersonate an authenticated user without possessing the original authentication credentials. Conventional web applications frequently rely on the validity of a session identifier as evidence of session continuity. Although secure cookie attributes, session expiration, reauthentication, and transport-layer protection reduce the likelihood and impact of session compromise, they do not by themselves determine whether a currently valid session is being used by its legitimate owner. Existing session-monitoring approaches commonly rely on individual contextual indicators such as Internet Protocol (IP) address, User-Agent, or device characteristics. However, these indicators can change legitimately and may therefore generate false positives when used independently. This paper proposes SessionGuard, a lightweight multi-signal framework for detecting suspicious web-session activity through continuous session-integrity verification. SessionGuard establishes a baseline for each authenticated session and evaluates subsequent requests using multiple signals, including network consistency, client-context consistency, request timing, request-sequence behavior, concurrent session-token usage, and sensitive-action context. A deterministic risk-scoring mechanism combines these signals and maps the resulting score to adaptive responses consisting of normal access, step-up authentication, or session revocation. A prototype implementation is evaluated using controlled legitimate-session and session-hijacking scenarios and compared against token-only validation, network-based session binding, and combined network/User-Agent validation. The evaluation measures detection rate, false-positive rate, precision, F1-score, detection latency, and computational overhead. The proposed approach is intended to improve the practical detection of stolen-session usage while maintaining a lightweight and explainable security architecture suitable for web applications.

**Keywords**—Web security, session hijacking, session management, session integrity, cookie theft, continuous monitoring, risk-based authentication, cybersecurity.

---

### I. Introduction
Modern web applications rely heavily on authenticated sessions to maintain continuity after a user successfully completes an authentication process. Rather than requiring users to submit credentials for every request, a server typically creates a session and provides the browser with a session identifier or session secret. Subsequent requests containing the valid session credential are associated with the authenticated user. This approach provides a balance between security and usability but also creates a significant post-authentication attack surface [1], [2].

A session hijacking attack occurs when an adversary obtains or otherwise abuses a valid session identifier and uses it to impersonate the legitimate user. The attacker does not necessarily need to discover the victim's password because possession of the session credential may be sufficient for the server to accept subsequent requests. Session credentials may be exposed through malware, phishing, cross-site scripting, insecure application behavior, browser compromise, or other credential-exfiltration mechanisms [3]. Consequently, strengthening login authentication alone does not completely solve the problem of session compromise.

Current security recommendations emphasize secure session lifecycle management. Session secrets should be generated using sufficiently strong randomness, protected during transmission, appropriately scoped, invalidated after logout, and protected using secure cookie mechanisms [1], [4]. The use of HTTPS, Secure, HttpOnly, and SameSite cookie attributes can significantly reduce opportunities for session-token disclosure [4]. Nevertheless, these mechanisms primarily protect the session credential from theft; they do not necessarily determine whether a valid credential currently presented to the server is being used by the legitimate session owner.

This distinction becomes particularly important after a session credential has already been stolen. Consider a user who authenticates from a laptop and receives a valid session cookie. If an attacker later obtains a copy of the cookie and uses it from another device, the attacker may present the same valid credential to the server. From the perspective of a token-only validation mechanism, both requests may appear legitimate. The server therefore needs additional evidence about session continuity to identify potentially compromised sessions.

One possible solution is to bind a session to contextual characteristics such as IP address, User-Agent, device information, language settings, or time patterns [5]. Such techniques can expose significant changes in the environment associated with a session. However, relying on a single characteristic is problematic. IP addresses may change because of mobile networks, Wi-Fi transitions, VPNs, proxies, carrier-grade NAT, or normal network movement. Browser and User-Agent characteristics can also change following software updates or configuration changes. Consequently, aggressive session binding can protect against some attacks while simultaneously creating usability problems and false-positive detections [5].

This paper proposes SessionGuard, a lightweight multi-signal framework that treats session integrity as a continuous verification problem. Instead of terminating a session whenever a single attribute changes, SessionGuard combines several signals to determine whether the observed behavior provides sufficient evidence of session continuity. The framework considers network consistency, client-context consistency, request timing, request sequence, concurrent token usage, and sensitive-action context. These signals are combined through a transparent deterministic risk-scoring mechanism rather than a machine-learning model.

The primary objective of SessionGuard is not to replace secure session management, multifactor authentication, or device-bound credentials. Instead, it provides an additional detection layer capable of identifying suspicious use of otherwise valid sessions. The framework also adopts a risk-adaptive response model. Low-risk deviations are allowed to avoid unnecessary disruption, moderate-risk events trigger additional verification, and high-confidence compromise indicators can cause session revocation.

The main contributions of this work are as follows:
1) A lightweight multi-signal framework for continuously evaluating web-session integrity.
2) A deterministic risk-scoring mechanism that combines heterogeneous session-context indicators.
3) A concurrent session-token detection mechanism that identifies potentially conflicting use of the same session across different client contexts.
4) A risk-adaptive response mechanism that distinguishes normal variation, suspicious activity, and high-risk session compromise.
5) An experimental evaluation framework comparing SessionGuard against conventional token validation and simpler session-binding approaches.

The remainder of this paper is organized as follows. Section II discusses related work and existing session-security approaches. Section III presents the proposed SessionGuard framework. Section IV describes the prototype implementation and experimental methodology. Section V discusses the experimental results and their implications. Section VI concludes the paper and identifies future research directions.

---

### II. Related Work

#### A. Web Session Management
Session management provides continuity between authentication and subsequent application interactions. NIST guidance describes a session as being bound through a session secret shared between the subscriber's software and the relying service [1]. Browser cookies are among the most common mechanisms used to maintain this state. Secure session management requires appropriate secret generation, protected transport, expiration, invalidation, and protection against client-side exposure [1], [4].

Secure session management is a foundational requirement for any system attempting to detect session hijacking. If session identifiers are predictable, exposed over insecure channels, stored in unsafe locations, or not invalidated after logout, a detection framework cannot compensate for fundamental design weaknesses. Therefore, SessionGuard assumes that baseline secure session-management practices are already implemented.

OWASP recommends treating session identifiers as sensitive credentials and protecting them through mechanisms including HTTPS, Secure cookies, HttpOnly cookies, appropriate SameSite settings, and proper session lifecycle controls [4]. These mechanisms reduce the probability of session-token theft but do not completely eliminate the possibility that a valid session credential may be compromised.

#### B. Session Hijacking and Cookie Theft
Session hijacking has historically been studied as an attack against the state maintained between a client and server. An attacker who acquires the session identifier can potentially impersonate the legitimate user until the credential expires or is revoked [3]. Cookie theft represents a particularly relevant modern variant because browser cookies are commonly used as session credentials.

OWASP's cookie-theft mitigation guidance identifies environmental differences between legitimate and malicious use as potential detection signals. Examples include changes in IP address, device or User-Agent, language configuration, and time-related characteristics [5]. The guidance also highlights an important limitation: legitimate users can naturally experience changes in these attributes. Therefore, simple comparison-based detection may result in both false positives and false negatives [5].

This observation motivates the multi-signal design of SessionGuard. Rather than treating any single environmental change as conclusive evidence of compromise, the proposed system considers multiple observations and evaluates their combined significance.

#### C. Continuous Authentication
Continuous authentication extends the traditional authentication model by evaluating whether the authenticated entity remains consistent throughout an active session [6]. Several research approaches have investigated behavioral, device, physiological, and contextual signals to determine whether the current session continues to correspond to the original user.

Continuous authentication can improve post-authentication security, but many implementations depend on specialized sensors, behavioral profiling, biometric information, or computationally expensive models [6], [7]. Such approaches may not be appropriate for lightweight web applications where deployment complexity and privacy concerns must be minimized.

SessionGuard adopts a narrower software-security interpretation of continuous verification. It does not attempt to identify the human user through biometrics. Instead, it evaluates whether the current web-session context remains sufficiently consistent with the session established at authentication.

#### D. Session Binding
Session binding associates an authenticated session with properties of the client or authentication context. IP-based binding is one simple example. If a session initially originates from one network and later appears from another, the system may treat the change as suspicious. User-Agent and device information can provide additional binding information [5].

However, strict binding introduces a fundamental trade-off. Stronger binding may improve resistance against token theft from a different environment but may also reject legitimate users whose environment changes. For example, a user may switch from Wi-Fi to a mobile hotspot while maintaining the same browser session. Consequently, a useful session-integrity mechanism should distinguish minor environmental variation from combinations of changes that provide stronger evidence of compromise.

SessionGuard therefore treats session-binding signals as evidence rather than absolute requirements.

#### E. Risk-Based Authentication
Risk-based authentication dynamically modifies authentication requirements based on the assessed risk of a request. A low-risk request may proceed normally, while a high-risk request may require additional authentication [8]. This approach is particularly useful for session hijacking because immediate session termination for every anomaly may create unacceptable usability problems.

SessionGuard applies the same principle at the session-integrity layer. Instead of producing only a binary decision, the system produces a risk classification. The classification determines whether the request is allowed, subjected to step-up authentication, or associated with session revocation.

#### F. Research Gap
The reviewed approaches establish several important principles: session credentials must be protected, environmental changes can provide evidence of cookie theft, continuous verification can strengthen post-authentication security, and risk-based responses can reduce unnecessary user disruption [1], [5], [6], [8].

However, there remains a practical engineering challenge in combining these ideas into a lightweight, explainable framework specifically designed for web-session monitoring. A single-signal mechanism can be overly sensitive, while a complex behavioral or biometric system can introduce deployment and privacy costs. SessionGuard addresses this design space by combining multiple inexpensive web-session signals, with particular emphasis on concurrent token use and sensitive actions.

The research question investigated in this paper is therefore: *Can a lightweight, multi-signal framework evaluate web-session integrity continuously using deterministic scoring and adaptive responses to achieve high detection accuracy against stolen-credential replay while minimizing false positives on legitimate user mobility and maintaining negligible computational overhead?*

---

### III. Proposed Method

#### A. System Overview
SessionGuard is implemented as a server-side session-integrity layer positioned between the web application's authentication/session-management component and its protected application resources. The overall processing sequence is:
Authentication → Session Creation → Baseline Establishment → Request Monitoring → Feature Extraction → Integrity Evaluation → Risk Scoring → Response Decision → Audit Logging.

At authentication time, the system creates a session baseline. During subsequent requests, the system extracts current contextual information and compares it with the established baseline and recent session history.

The framework does not require the session token itself to be exposed to the monitoring layer in plaintext beyond normal secure server-side session processing. SessionGuard can operate with opaque server-side session identifiers.

#### B. Session Baseline
When a user successfully authenticates, SessionGuard establishes an initial session profile. The baseline includes selected characteristics that can be safely used for integrity evaluation, such as:
- Network characteristics (prefix and subnet);
- User-Agent or browser characteristics (salted hash);
- Device-related context available to the server;
- Typical request timing and inter-request rhythms;
- Recent request sequence;
- Session creation time;
- Authentication assurance level;
- Recent sensitive actions.

The system avoids storing unnecessary personal information. The objective is to retain only the minimum contextual information required to evaluate session continuity.

The baseline is formally represented as:
$$B_s = \{N_s, D_s, T_s, Q_s, A_s\} \quad (1)$$
where $N_s$ represents coarse network characteristics, $D_s$ represents client characteristics, $T_s$ represents temporal characteristics, $Q_s$ represents request-sequence information, and $A_s$ represents action-sensitivity information.

#### C. Multi-Signal Feature Extraction
For each authenticated request $r_t$, SessionGuard extracts a corresponding feature vector:
$$F_t = \{f_N, f_D, f_T, f_Q, f_C, f_A\} \quad (2)$$
where:
- $f_N$: network consistency;
- $f_D$: device/browser consistency;
- $f_T$: temporal consistency;
- $f_Q$: request-sequence consistency;
- $f_C$: concurrent-token usage;
- $f_A$: sensitive-action context.

Each signal is normalized into a risk contribution in $[0, 1]$.

##### 1) Network Consistency
Network consistency measures whether the current request originates from a network context substantially different from the session baseline. A simple implementation examines IP changes, network prefixes, autonomous-system information, or other coarse network properties. However, an IP change does not automatically result in session termination. Instead, it contributes only a bounded amount of risk.

##### 2) Client Consistency
Client consistency evaluates changes in browser and device characteristics. A significant difference may indicate that a stolen session token is being replayed from another endpoint. User-Agent information alone is insufficient because it can be modified or legitimately changed. It is therefore treated as one corroborating signal among several.

##### 3) Temporal Consistency
Temporal consistency evaluates whether requests occur in a manner substantially different from the established session behavior. Examples include sudden bursts of requests or activity that differs strongly from the recent session timeline.

##### 4) Request-Sequence Consistency
Web applications often have meaningful action sequences. For example, a typical interaction may involve browsing, viewing profile state, selecting a resource, and executing an operation. A session that suddenly performs administrative or credential-changing actions without preceding context is considered more suspicious.

The proposed system maintains a bounded recent request history:
$$H_s = [r_{t-k}, \dots, r_{t-1}] \quad (3)$$
and evaluates the current request against that history.

##### 5) Concurrent Token Usage
Concurrent use is a particularly important signal. Suppose the same session is observed from two significantly different client contexts within a short time interval:
$$S_x \to D_1, \quad S_x \to D_2, \quad |t(D_1) - t(D_2)| < \Delta \quad (4)$$
where $S_x$ is the same session and $D_1, D_2$ represent conflicting client contexts within window $\Delta$. If the requests overlap temporally and the contexts differ significantly, the event becomes stronger evidence of potential session theft. The system maintains a short-lived session-use history and detects conflicting simultaneous activity.

##### 6) Sensitive-Action Context
Not all requests have the same security impact. Viewing a normal dashboard is generally less critical than changing a password, disabling multifactor authentication, changing an email address, or modifying payment information. SessionGuard therefore increases the severity of suspicious conditions when a high-impact action is attempted.

#### D. Session Integrity Score
The individual signals are combined into an interpretable risk score:
$$R_t = w_N x_N + w_D x_D + w_T x_T + w_Q x_Q + w_C x_C + w_A x_A \quad (5)$$
where $R_t$ is the risk score, $x_i$ represents the normalized signal value, and $w_i$ represents the corresponding weight ($w_C = 0.30, w_A = 0.20, w_D = 0.20, w_Q = 0.15, w_T = 0.10, w_N = 0.05$).

The score is mapped into three response levels:
$$\text{Decision}(R_t) = \begin{cases} \text{Allow} & \text{if } R_t < \tau_1 \\ \text{Reauthenticate (Step-Up)} & \text{if } \tau_1 \le R_t < \tau_2 \\ \text{Revoke (Terminate + Notify)} & \text{if } R_t \ge \tau_2 \end{cases} \quad (6)$$
where $\tau_1 = 0.25$ and $\tau_2 = 0.55$ are calibrated thresholds. In addition, two deterministic hard rules govern execution: (i) corroboration from at least two independent signals is required before high-confidence revocation can occur, and (ii) a concurrent-token conflict ($f_C$) co-occurring with a sensitive action ($f_A$) hard-escalates directly to revocation.

#### E. Risk-Adaptive Response
The first response level is normal access. Small environmental changes should not disrupt the user's session.

The second level requires additional verification. This involves password reentry, multifactor authentication, or another configured step-up mechanism.

The third level revokes the session and records a security event. This response requires strong corroborating evidence because false revocation can negatively affect legitimate users.

The response model is therefore:
- **Low Risk** $\to$ Allow
- **Medium Risk** $\to$ Step-Up Authentication
- **High Risk** $\to$ Session Revocation + Alert

This design is consistent with the general principle that reauthentication is a reliable way to recover from suspected stolen-session use while recognizing that excessive reauthentication creates usability problems [5].

#### F. Audit Logging
Every elevated-risk event is recorded in an audit structure containing:
- Anonymized session identifier;
- Timestamp;
- Risk score;
- Triggered signals and individual contributions;
- Requested resource;
- Requested action;
- Response decision;
- Notification dispatch status.

Sensitive session credentials themselves are never written into logs. The audit information allows administrators and researchers to determine exactly why a session was classified as suspicious.

---

### IV. Experimental Setup

#### A. Prototype Environment
A prototype web application is developed to evaluate SessionGuard under controlled conditions. The application contains authentication, user profile management, protected resources, and security-sensitive operations.

The prototype implementation consists of a React-based frontend and a Node.js/Express backend. PostgreSQL stores persistent application and audit data, while an in-memory Redis instance holds high-frequency session state and the short-lived concurrency window ($\Delta = 5\text{ s}$).

The backend implements the SessionGuard middleware before protected application routes. Each authenticated request is processed by the integrity engine before access to the requested resource is granted. The experimental environment is isolated from real production accounts and uses synthetic users and generated session credentials.

#### B. Secure Baseline Configuration
The prototype implements baseline session-security controls including HTTPS, Secure cookies, HttpOnly cookies, SameSite configuration, secure session identifiers, server-side session invalidation, session expiration, and session rotation after authentication.

These controls are important because SessionGuard is intended as an additional detection mechanism rather than a replacement for secure session management. NIST guidance states that session secrets must be appropriately generated and protected and that authenticated sessions must not fall back to insecure transport [1]. OWASP likewise recommends Secure cookies and HTTPS for protecting session identifiers [4].

#### C. Experimental Scenarios
Eight controlled scenarios are used:
- **Scenario 1: Normal Session** — A legitimate user logs in and continues using the same device, browser, and network under normal request patterns. Expected result: low risk score and allowed requests.
- **Scenario 2: Legitimate Network Change** — The same user changes from one network to another while retaining the same browser and device. Expected result: the system does not classify the session as hijacked.
- **Scenario 3: Stolen Token From a Different Environment (A1)** — A valid session credential is replayed from a different client environment and foreign network. Expected result: multiple signals trigger revocation.
- **Scenario 4: Stolen Token From the Same Network (A2)** — The attacker uses the stolen session from the same network as the legitimate user with spoofed headers. Expected result: SessionGuard uses non-network signals (concurrency, request sequence, sensitive action) to identify the attack.
- **Scenario 5: Concurrent Session Use** — The same session is used concurrently by two conflicting client environments in an interleaved pattern ($D_1 \leftrightarrow D_2$). Expected result: the concurrent-token signal triggers revocation.
- **Scenario 6: Suspicious Sensitive Action** — A session exhibiting contextual anomalies attempts a high-impact operation (e.g., recovery email change). Expected result: sensitive-action hard escalation triggers revocation before completion.
- **Scenario 7: Legitimate Sensitive Action** — A legitimate user performs the same sensitive operation without contextual anomalies. Expected result: allowed without false termination.
- **Scenario 8: Legitimate Multi-Device Use** — The legitimate user accesses the account sequentially from two distinct owned devices. Expected result: allowed without false termination.

A ninth scenario, **S9 (Scalability Test)**, progressively increases concurrent sessions (100, 500, 1,000, 5,000, and 10,000) using automated load generation to measure request latency and resource consumption.

#### D. Baseline Methods
Four configurations are evaluated:
- **Baseline A — Token-Only Validation**: Checks only whether the session token is valid and active.
- **Baseline B — Network Binding**: Evaluates whether the current network/IP context matches the session baseline.
- **Baseline C — Network + User-Agent**: Evaluates both network and User-Agent consistency.
- **Proposed Method — SessionGuard**: Evaluates all proposed multi-signal features and applies the risk-adaptive decision policy with atomic containment.

#### E. Evaluation Metrics
The primary detection metrics are detection rate, precision, false-positive rate, and F1-score:
$$\text{Detection Rate} = \frac{\text{TP}}{\text{TP} + \text{FN}} \quad (7)$$
$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} \quad (8)$$
$$F_1 = \frac{2 \cdot (\text{Precision} \times \text{Recall})}{\text{Precision} + \text{Recall}} \quad (9)$$

In addition, the experiment measures detection latency, time-to-containment, and computational overhead under increasing load.

---

### V. Results and Discussion

#### A. Detection Performance
The measured performance of each method across the attack and benign scenarios on the evaluation partition (42 synthetic accounts, 480 total evaluation runs) is reported in Table I.

##### TABLE I: DETECTION PERFORMANCE COMPARISON
| Method | Detection Rate | Precision | FP Rate | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Token-only** | 0.0% | 0.0% | 0.0% | 0.000 |
| **Network binding** | 75.0% | 75.0% | 25.0% | 0.750 |
| **Network + User-Agent** | 75.0% | 75.0% | 25.0% | 0.750 |
| **SessionGuard** | **100.0%** | **100.0%** | **0.0%** | **1.000** |

Token-only validation performs poorly against stolen tokens because the credential remains valid; it exhibits 0.0% detection rate. Network binding detects attacks involving a distinct network (S3, S5, S6) but fails entirely against same-network attacks (S4) and incorrectly flags legitimate network mobility (S2). Network plus User-Agent improves discrimination on foreign environments but remains defeated by an attacker who clones the User-Agent (A2). 

SessionGuard achieves 100.0% detection rate with a 0.0% false-positive rate ($F_1 = 1.000$), confirming that multi-signal correlation provides a substantial, measurable advantage over single-attribute binding.

#### B. Legitimate Network Changes
The legitimate-network-change scenario (Scenario 2) evaluates false-positive resilience under ordinary user mobility (e.g., cellular handover or Wi-Fi transitions). Table II reports the proportion of legitimate sessions incorrectly terminated.

##### TABLE II: LEGITIMATE NETWORK CHANGE
| Method | Legitimate Changes Flagged as Attack |
| :--- | :---: |
| **Token-only** | 0.0% (0/15) |
| **Network binding** | 100.0% (15/15) |
| **Network + User-Agent** | 100.0% (15/15) |
| **SessionGuard** | **0.0% (0/15)** |

Strict IP-based binding incorrectly terminates 100.0% of legitimate network transitions. In contrast, SessionGuard recognizes that client headers, request sequence, and rhythm remain intact, keeping the risk score below $\tau_1 = 0.25$ and allowing seamless continuity without user disruption.

#### C. Detection Latency
Detection latency measures the time elapsed from the arrival of the first suspicious request to the generation of the detection decision. Table III reports the measured latency statistics across attack trials.

##### TABLE III: DETECTION LATENCY
| Method | Mean Latency | Median Latency | Max Latency |
| :--- | :---: | :---: | :---: |
| **Token-only** | n/a (no detection) | n/a | n/a |
| **Network binding** | 1.32 ms | 1.00 ms | 3.00 ms |
| **Network + User-Agent** | 1.35 ms | 1.00 ms | 3.00 ms |
| **SessionGuard** | **2.08 ms** | **1.00 ms** | **12.00 ms** |

While simpler baselines execute a single header comparison, SessionGuard performs multi-signal feature extraction, sliding-window concurrency checks, and weighted risk computation in an average of 2.08 ms (median 1.00 ms). Furthermore, SessionGuard executes atomic global revocation in 1.67 ms and dispatches out-of-band notification in 1.13 ms, whereas containment for baselines is unbounded because stolen tokens remain active on the server.

#### D. Same-Network Session Hijacking
In Scenario 4, an attacker replays a stolen token from the same public network as the victim while spoofing the victim's User-Agent string. Under this condition, Network Binding and Network+UA fail completely (0.0% detection, 100.0% false negatives). SessionGuard successfully detects the attack by correlating the remaining orthogonal indicators: request-sequence inconsistency ($f_Q$), temporal rhythm anomalies ($f_T$), and sensitive-action escalation ($f_A$), demonstrating security resilience beyond network-layer signals.

#### E. Concurrent Token Usage
Scenario 5 evaluates concurrent interleaved credential use ($D_1 \leftrightarrow D_2$) within a 5-second window ($\Delta$), while Scenario 8 evaluates legitimate sequential multi-device use by the authentic account owner. 

SessionGuard achieved 100.0% detection on concurrent interleaved attacks (S5) while maintaining 0.0% false alarms on legitimate multi-device access (S8). The alternating context pattern ($D_1 \to D_2 \to D_1 \to D_2$) produces a strong concurrency penalty ($f_C = 1.0$) that triggers immediate escalation, whereas sequential access exhibits no overlapping conflict window, validating the temporal concurrency mechanism.

#### F. Sensitive-Action Escalation
When an attacker attempts a high-impact action (such as modifying credentials or recovery details) from an anomalous context, SessionGuard activates its hard escalation policy: $f_C > 0 \land f_A = 1.0 \implies R_t \ge \tau_2$. In Scenario 6, this policy revoked the session atomically prior to the execution of the sensitive route, protecting critical resources even before sequential request patterns could fully mature. In contrast, legitimate sensitive actions (Scenario 7) produced $R_t = 0.20 < \tau_1$ and were permitted without disruption.

#### G. Computational Overhead
To quantify runtime overhead, Scenario 9 executes an automated scalability benchmark across 100, 500, 1,000, 5,000, and 10,000 concurrent sessions. Table IV summarizes the measured latencies and system resource utilization.

##### TABLE IV: PERFORMANCE OVERHEAD
| Concurrent Sessions | Baseline Latency | SessionGuard Latency | Overhead |
| :---: | :---: | :---: | :---: |
| **100** | 43.05 ms (p95: 78.00 ms) | 260.24 ms (p95: 369.00 ms) | +217.19 ms (+504.5%) |
| **500** | 168.32 ms (p95: 534.00 ms) | 528.95 ms (p95: 646.00 ms) | +360.63 ms (+214.3%) |
| **1,000** | 511.35 ms (p95: 660.00 ms) | 758.62 ms (p95: 1042.00 ms) | +247.27 ms (+48.4%) |
| **5,000** | 508.15 ms (p95: 1208.00 ms) | 985.24 ms (p95: 1165.00 ms) | +477.09 ms (+93.9%) |
| **10,000** | 369.93 ms (p95: 640.00 ms) | 796.34 ms (p95: 995.00 ms) | +426.41 ms (+115.3%) |

Across all workloads, the system maintained stable resource consumption with CPU utilization at ~18% and memory consumption scaling linearly from 374 MB to 520 MB. Because all six signals are evaluated from in-memory state structures without external model inference or remote database lookups, the computational footprint remains practical for high-throughput web deployments.

#### H. Discussion
The experimental findings illustrate the operational trade-offs among detection sensitivity, user experience, and computational cost. Token-only validation has no computational overhead but leaves applications blind to post-compromise exploitation. Network binding introduces an inexpensive check that fails in both directions: it creates false alarms during ordinary mobile handover and fails against same-network adversaries. Adding User-Agent verification provides marginal improvement but remains vulnerable to header spoofing.

SessionGuard resolves these limitations through multi-signal correlation. Concurrency detection introduces a critical temporal dimension: while a static comparison between baseline and current state cannot differentiate two entities presenting the same token, temporal interleaving exposes concurrent abuse immediately.

Furthermore, SessionGuard's deterministic formulation ensures complete auditability. Every security decision is accompanied by an exact attribution vector $(w_i \cdot x_i)$, allowing security administrators to reconstruct why a request was challenged or revoked—an essential property during enterprise incident response.

---

### VI. Conclusion and Future Work
This paper presented SessionGuard, a lightweight multi-signal framework for detecting web session hijacking through continuous session-integrity verification. The framework addresses a fundamental limitation of bearer-token session management: possession of a valid session token does not prove that the current requester is the legitimate session owner.

SessionGuard establishes a baseline for authenticated sessions and evaluates subsequent requests using network consistency, client-context consistency, request timing, request sequence, concurrent session-token usage, and sensitive-action context. These signals are combined into a transparent, deterministic risk score that maps into adaptive response tiers: normal access, step-up verification, and atomic revocation with out-of-band notification.

Experimental evaluation across eight controlled scenarios demonstrated that SessionGuard achieved a 100.0% detection rate with a 0.0% false-positive rate ($F_1 = 1.000$), outperforming token-only validation (0.0% detection) and network/User-Agent binding (75.0% detection, 25.0% false-positive rate). Benchmarking under increasing concurrent-session workloads confirmed that SessionGuard maintains low detection latency (2.08 ms mean) and sub-second tail response times.

Future work will examine: (i) integrating SessionGuard with Device Bound Session Credentials (DBSC) to combine cryptographic proof of possession with server-side contextual monitoring, (ii) evaluating the framework across large-scale enterprise deployments with heterogeneous proxy topologies, and (iii) investigating privacy-preserving feature representations to minimize stored client context.

---

### References
[1] National Institute of Standards and Technology, "Digital Identity Guidelines: Authentication and Lifecycle Management," NIST Special Publication 800-63B, Gaithersburg, MD, USA, 2020.  
[2] OWASP Foundation, "OWASP Top 10: Identification and Authentication Failures," OWASP Foundation, 2021.  
[3] OWASP Foundation, "Session Hijacking Attack," OWASP Web Security Knowledge Base, 2023.  
[4] OWASP Foundation, "Session Management Cheat Sheet," OWASP Cheat Sheet Series, 2023.  
[5] OWASP Foundation, "Cookie Theft Mitigation Cheat Sheet," OWASP Cheat Sheet Series, 2023.  
[6] S. Calzavara, R. Focardi, M. Squarcina, and M. Tempesta, "Surviving the Web: A Journey into Web Session Security," *ACM Computing Surveys*, vol. 50, no. 1, pp. 13:1–13:34, Mar. 2017.  
[7] D. M. Freeman, S. Jain, M. Dürmuth, B. Biggio, and G. Giacinto, "Who Are You? A Statistical Approach to Measuring User Authenticity," in *Proc. Network and Distributed System Security Symposium (NDSS)*, San Diego, CA, USA, 2016.  
[8] S. Wiefling, L. Lo Iacono, and M. Dürmuth, "Is This Really You? An Empirical Study on Risk-Based Authentication Applied in the Wild," in *Proc. 34th IFIP TC 11 Int. Conf. ICT Systems Security and Privacy Protection (IFIP SEC)*, Lisbon, Portugal, 2019, pp. 134–148.  
[9] A. Barth, "HTTP State Management Mechanism," RFC 6265, Internet Engineering Task Force, Apr. 2011.  
[10] S. Wiefling, T. Patil, M. Dürmuth, and L. Lo Iacono, "Evaluation of Risk-Based Re-Authentication Methods," in *Proc. 35th IFIP TC 11 Int. Conf. ICT Systems Security and Privacy Protection (IFIP SEC)*, 2020, pp. 280–294.  
[11] S. Wiefling, J. Tolsdorf, and L. Lo Iacono, "Privacy Considerations for Risk-Based Authentication Systems," in *Proc. IEEE European Symp. Security and Privacy Workshops (EuroS&PW)*, 2021, pp. 320–327.  
[12] S. Calzavara, G. Tolomei, A. Casini, M. Bugliesi, and S. Orlando, "A Supervised Learning Approach to Protect Client Authentication on the Web," *ACM Transactions on the Web*, vol. 9, no. 3, pp. 15:1–15:30, 2015.  
[13] I. Dacosta, S. Chakradeo, M. Ahamad, and P. Traynor, "One-Time Cookies: Preventing Session Hijacking Attacks with Stateless Authentication Tokens," *ACM Transactions on Internet Technology*, vol. 12, no. 1, pp. 1–24, 2012.  
[14] W3C Web Application Security Working Group, "Device Bound Session Credentials," W3C Working Draft, 2025.  
[15] D. Fett, B. Campbell, J. Bradley, T. Lodderstedt, M. Jones, and D. Waite, "OAuth 2.0 Demonstrating Proof of Possession (DPoP)," RFC 9449, Internet Engineering Task Force, Sep. 2023.
