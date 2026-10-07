# Project Timeline

**Project:** DDoS Detection in Software-Defined Networks — SDN Shield

**Proposed duration:** 12 weeks

**Status:** Planned work; the deliverables below have not yet been completed.

This timeline is an assumption because start and submission dates have not been specified. If the available time changes, optional work will be removed first; the three detection methods, automatic mitigation, and core measurements will remain in scope.

See the [README](README.md) for the project scope and experimental methodology.

## Weekly work plan

| Week | Work | Owners | Verifiable deliverable |
| --- | --- | --- | --- |
| 1 | Set up the isolated Linux lab; define the topology, traffic features, window labels, and event-record format | Entire team; environment: Mustafa | Connectivity between Mininet hosts; lab isolated from external networks; shared experiment configuration |
| 2 | Evaluate the Rust OpenFlow library; test OVS connectivity, basic forwarding, statistics collection, and drop rules | Semih, Mustafa, Hammad | End-to-end smoke test on one switch; recorded software/protocol versions |
| 3 | Validate multi-host integration; record counter deltas and alarm/mitigation timestamps; make the controller decision | Semih, Hammad; traffic: Mustafa | Traffic → observation → drop → recovery workflow; decision to continue with Rust or switch to a ready-made controller |
| 4 | Complete normal and high-volume legitimate traffic profiles; prepare SYN/UDP/ICMP flood scenarios with rate and duration limits | Mustafa; measurements: Hammad; integration: Semih | Labeled, repeatable scenarios and attack-free baseline measurements |
| 5 | Implement shared feature extraction and threshold-based detection; select thresholds using calibration data only | Baki, Semih; data: Mustafa | Threshold results on normal, high-volume legitimate, and attack records; alarm logs |
| 6 | Implement entropy-based detection; validate distributions and reference profiles | Baki, Semih | Threshold/entropy comparison on the same records; frozen entropy parameters |
| 7 | Split data by experiment run; train a simple ML model and integrate inference | Baki, Semih; records: Hammad | Training/validation/test split, saved model, and shared output format for all three methods |
| 8 | Connect all three methods to automatic mitigation; test rule scope, lifetime, verification, and cleanup | Hammad, Semih; scenarios: Mustafa; detection: Baki | Attack-blocking and normal traffic recovery tests for each method |
| 9 | Run pilot experiments; fix missing metrics and measurement errors; freeze the test configuration | Hammad; support: entire team | End-to-end pilot results; fixed repetition count, run order, and test parameters |
| 10 | Run the full experiment matrix; compare detection with mitigation disabled and conduct end-to-end tests with mitigation enabled | Mustafa, Hammad; support: Semih, Baki | At least five independent runs per condition; raw records and resource-usage data |
| 11 | Analyze results; investigate inconsistent runs; conduct the optional comparison if time permits | Baki, Hammad; optional controller work: Semih; environment: Mustafa | Accuracy/FPR/latency/user-impact/CPU/RSS tables and charts |
| 12 | Prepare the final report and demo; verify reproducibility in a clean environment | Entire team | Working demo, experiment instructions, final report, and documented limitations |

## Milestones and acceptance criteria

### M1 — Lab and controller decision · End of Week 3

- Normal hosts can communicate through the selected controller.
- Switch statistics can be collected regularly.
- A drop rule blocks the intended traffic; connectivity returns after cleanup.
- If this workflow is unreliable in Rust, switch to a ready-made controller. Prioritize the transition in Week 4 and cancel optional work.

### M2 — Three detection methods · End of Week 7

- Threshold, entropy, and simple ML use the same feature/label contract.
- High-volume legitimate traffic is included in calibration and evaluation.
- Test runs are not used for training or threshold selection.
- Each method reports the alarm time and associated traffic group in a shared format.

### M3 — Integrated mitigation and measurement · End of Week 9

- All three methods are connected to the OpenFlow mitigation workflow.
- Rule processing and actual traffic blocking are verified separately.
- Detection latency, mitigation latency, legitimate traffic impact, and CPU/RSS records are available.
- Rules are cleaned up between experiments, and the network can return to its baseline state.

### M4 — Experiments and delivery · End of Week 12

- Normal, high-volume legitimate, SYN flood, UDP flood, and ICMP flood conditions have been completed.
- Independent legitimate user traffic has also been measured during attacks.
- Experiments have been repeated; missed attacks and false alarms have been reported.
- Results can be reproduced using the source code, configurations, and raw records.

Numerical accuracy and latency targets have not yet been defined. They will be agreed upon after baseline measurements and before final testing, and will not be changed afterward to fit the observed results.

## Dependencies and parallel work

- While controller integration is underway, Mustafa can prepare the topology and traffic scenarios, Baki can develop methods using recorded/synthetic features, and Hammad can prepare event logging and metric calculations.
- Live detection requires statistics collection; ML requires labeled data; end-to-end benchmarking requires integrated detection and mitigation.
- Threshold and entropy will share feature extraction. ML will use the same observable features.
- If the controller changes, shared feature and event formats will be preserved to avoid rewriting the algorithm comparison.

## Risks and time management

| Risk | Mitigation / decision |
| --- | --- |
| Rust OpenFlow integration takes too long | Week 3 decision gate; switch to a ready-made controller if necessary |
| Counters do not provide the required features | Validate observability in the first three weeks; use bounded sampling or available features if necessary |
| Insufficient or homogeneous ML data | Collect records across different rates and host counts; split by run; keep the model simple |
| False alarms under high-volume legitimate traffic | Include this profile in calibration and independent tests |
| Broad drop rules disrupt legitimate traffic | Narrow rule matches, set rule lifetimes, and measure user impact |
| Resource contention on a single server | Record server load and CPU placement; keep experiment conditions fixed |
| Schedule pressure | Remove optional work first; reserve Weeks 11–12 for analysis, corrections, and delivery |

## Only if time permits

1. **Rust–Ryu comparison:** If the Rust controller is completed, compare response time and CPU/RSS using the same topology, traffic, detection/mitigation logic, and measurement intervals.
2. **High-volume Packet-In scenario:** Run a controller-load experiment separate from the main scope; report it separately from the core DDoS results.

These tasks are not prerequisites for the main deliverable.
