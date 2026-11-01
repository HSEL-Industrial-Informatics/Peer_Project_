# OPC UA Protocol Inference and State Machine Learning

**Project:** Peer Project (10 CP)\
**Institution:** Hochschule Emden/Leer\
**Programme:** M.Sc. Industrial Informatics\
**Proposal date:** 18 November 2025

## 1. Overview

This repository collects the source code, packet captures, processed
data, learned models, visualisations, experiments, and documentation for
the project **Protocol Inference and State Machine Learning of the OPC
UA Protocol from Network Traces**.

The project investigates how OPC UA protocol behaviour can be
represented as a finite-state model using network-traffic analysis and
automata-learning techniques.

The proposed workflow includes:

1.  Establishing a controlled OPC UA client/server test environment.
2.  Capturing OPC UA network traffic in PCAP/PCAPNG format.
3.  Preprocessing traffic and extracting OPC UA messages.
4.  Identifying message types and relevant fields.
5.  Mapping concrete messages to an abstract alphabet.
6.  Inferring a state-machine model from observed behaviour.
7.  Validating and documenting the model.

This repository also contains an active-learning implementation using
AALpy. **Models inferred from recorded PCAP traces and models learned
through active interaction with an OPC UA server are distinct results
and should be labelled separately.**

## 2. Objectives

-   Define the OPC UA services and behaviours included in the
    experiments.
-   Create repeatable client/server interaction scenarios.
-   Capture and analyse traffic using Wireshark and related tools.
-   Extract OPC UA messages from packet captures.
-   Develop an abstraction from concrete messages to symbols.
-   Investigate passive inference from recorded traces.
-   Use AALpy for active learning and model refinement where applicable.
-   Visualise state machines using Graphviz.
-   Validate models against additional traces and/or a separate OPC UA
    server.
-   Document assumptions, limitations, and results.

## 3. Experimental Environment

The experimental work has involved the following components. Update this
table to reflect the final setup.

  -----------------------------------------------------------------------
  Component                           Purpose
  ----------------------------------- -----------------------------------
  Prosys OPC UA Simulation Server     Main OPC UA server for experiments

  UaExpert                            OPC UA client for generating and
                                      testing interactions

  Python                              Traffic processing and experiment
                                      automation

  `asyncua`                           Python OPC UA communication library
                                      used by the client harness

  AALpy                               Active automata learning

  Wireshark                           Network traffic capture and
                                      inspection

  TShark                              Command-line packet extraction

  Scapy / PyShark                     Python packet processing, where
                                      used

  Graphviz                            State-machine visualisation
  -----------------------------------------------------------------------

### Security configuration

Some experiments use **Basic256Sha256** with **SignAndEncrypt**,
certificate-based secure-channel configuration, and username
authentication.

Encrypted captures may not expose service-level request and response
details unless suitable decryption material and supported analysis are
available. Record which captures are encrypted and which fields can
actually be decoded. Do not assume service names can be recovered from
encrypted payloads.

## 4. Suggested Repository Structure

``` text
opcua-protocol-inference/
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── project-proposal.pdf
│   ├── project-report.pdf
│   ├── requirements.md
│   ├── experimental-setup.md
│   └── methodology.md
├── captures/
│   ├── README.md
│   ├── raw/
│   └── processed/
├── src/
│   ├── capture/
│   ├── extraction/
│   ├── preprocessing/
│   ├── abstraction/
│   ├── passive_learning/
│   ├── active_learning/
│   └── validation/
├── models/
│   ├── passive/
│   ├── active/
│   └── comparison/
├── results/
│   ├── figures/
│   ├── tables/
│   ├── logs/
│   └── analysis/
├── tests/
├── requirements.txt
└── environment.yml
```

This is a suggested layout. Keep only directories and files that are
actually part of the repository.

## 5. Methodology

### 5.1 Traffic generation and capture

Generate repeatable OPC UA scenarios using the selected client and
server. Capture traffic with Wireshark or `tcpdump` and store original
captures in `captures/raw/`.

Suggested scenario categories:

-   Connection establishment and termination
-   Secure-channel and session establishment
-   Address-space browsing
-   Variable reads and writes
-   Subscription and monitored-item operations
-   Reconnection and recovery
-   Invalid operations and error responses

For each capture, record the client/server versions, endpoint, security
policy, message-security mode, authentication method, scenario steps,
and capture date. Do not publish passwords, private keys, or unredacted
credentials.

### 5.2 Packet processing and message extraction

Process captures to identify TCP streams and OPC UA messages. Where
required, handle TCP stream reassembly, OPC UA message boundaries,
message direction, chunking, and request/response correlation.

Record extraction limitations. For encrypted traffic, distinguish fields
visible in packet headers from service-level information that cannot be
decoded.

### 5.3 Message abstraction

Map extracted messages into a documented abstract alphabet. The exact
symbols must be supported by fields available in the captures.

Illustrative transport-level symbols:

``` text
HEL
ACK
OPN
MSG
CLO
ERR
```

Where service-level messages can be decoded, the abstraction may
include:

``` text
BROWSE_REQ
BROWSE_RES
READ_REQ
READ_RES
WRITE_REQ
WRITE_RES
CREATE_SUB_REQ
CREATE_SUB_RES
```

These are examples, not a claim that every symbol is available in every
capture.

### 5.4 Passive inference from traces

Recorded traces provide observed sequences. A passive-learning workflow
can build an initial prefix-based model and use state-merging or another
suitable inference method to generalise beyond the exact recorded
sequences.

Document:

-   How traces are segmented into sessions.
-   How client inputs are distinguished from server outputs.
-   How request/response pairs are correlated.
-   How errors, timeouts, and incomplete traces are represented.
-   Which inference algorithm is used.
-   How the inferred model is evaluated on traces not used for training.

A state machine generated from a single observed trace is only a
representation of that trace; it is not, by itself, evidence of a
complete protocol model.

### 5.5 Active learning with AALpy

The active-learning implementation uses a client-side harness to execute
abstract operations against an OPC UA server and observe normalised
outputs. AALpy can learn a model through membership queries and an
approximate equivalence-testing strategy.

Keep this model clearly identified as **actively learned**. It is
methodologically different from a model inferred solely from recorded
PCAP traces.

### 5.6 Model validation and comparison

Compare the passive trace-derived model with the active AALpy model
where their alphabets and abstraction levels are compatible.

Possible evaluation criteria:

-   Whether held-out traces are accepted or correctly replayed.
-   Whether observed transitions are represented.
-   Whether invalid sequences produce expected error behaviour.
-   Whether repeated experiments produce consistent results.
-   Which states or transitions differ between models.
-   Whether differences arise from abstraction, encryption, missing
    traces, or server-specific behaviour.

## 6. Existing Active-Learning Work

The existing active-learning work has explored:

-   A Python OPC UA client harness using `asyncua`.
-   AALpy's L\* learning algorithm and Mealy-machine models.
-   Abstract operations including `CONNECT`, `DISCONNECT`, `READ`,
    `WRITE`, `BROWSE`, `CREATE_SUB`, `DELETE_SUB`, `CREATE_MON`, and
    `DELETE_MON`.
-   Basic256Sha256 SignAndEncrypt and username authentication in the
    secure test configuration.
-   Connection recovery after an interruption observed in the Prosys
    test environment.
-   Graphviz generation of the learned state-machine diagram.
-   Validation experiments using a separate OPC UA server.

The current abstract state representation uses connection and operation
flags, including browse completion, subscription existence, and
monitored-item existence. Interpret the learned states within this
abstraction and experimental setup; they are not a complete formal model
of every OPC UA implementation.

## 7. Network Traffic Analysis

Store packet-analysis scripts and outputs separately from raw captures.

For each analysis run, document:

-   Number of capture files processed.
-   Number of packets and recognised OPC UA messages.
-   Message/service categories counted.
-   Incomplete, malformed, or unrecognised records.
-   Whether each capture was encrypted.
-   Filters and exclusions applied.

A previous analysis run included 12 CSV exports and 3,677
parser-recognised entries. These are results from that particular run,
not total network packet counts. Re-run the analysis and update the
figures if the input captures or parser change.

## 8. Reproducibility

For reproducibility:

1.  Record Python and package versions.
2.  Include installation instructions and dependency files.
3.  Document server endpoint configuration without publishing
    credentials.
4.  Store scenario definitions and capture metadata.
5.  Keep raw captures unchanged and write processed outputs separately.
6.  Record commands and configuration used for each run.
7.  Separate training traces from validation traces.
8.  Document random seeds and learning limits where supported.

Example environment setup:

``` bash
python -m venv .venv
pip install -r requirements.txt
```

Add the actual execution commands for project scripts once their
filenames and arguments are finalised.

## 9. Results and Artifacts

Add links to actual outputs as they become available.

  Result                            Suggested location          Status
  --------------------------------- --------------------------- -------------------
  Raw PCAP/PCAPNG captures          `captures/raw/`             To be added
  Processed packet/message data     `captures/processed/`       To be added
  Message-abstraction definitions   `src/abstraction/`          To be added
  Passive inferred model            `models/passive/`           To be added
  Active AALpy model                `models/active/`            Add final files
  Graphviz source and diagrams      `results/figures/`          Add final files
  Evaluation and comparison         `results/analysis/`         To be added
  Final report                      `docs/project-report.pdf`   Add final version

## 10. Limitations to Consider

-   PCAP traces show only interactions that were captured; they do not
    automatically cover all possible protocol behaviours.
-   Encrypted OPC UA payloads can prevent service-level message
    extraction.
-   TCP segmentation, retransmissions, and OPC UA chunking must be
    handled correctly.
-   Request/response correlation can be difficult when captures are
    incomplete or begin mid-session.
-   A passive model may overfit observed traces if there are
    insufficient examples or no held-out validation data.
-   An active-learning model depends on the harness, reset behaviour,
    output abstraction, and equivalence-testing strategy.
-   Server-specific behaviour should not be presented as a universal OPC
    UA protocol requirement.

## 11. References

Useful starting points:

-   OPC Foundation --- OPC UA specifications:
    https://reference.opcfoundation.org/
-   AALpy --- Active Automata Learning in Python:
    https://github.com/DES-Lab/AALpy
-   Wireshark User's Guide: https://www.wireshark.org/docs/
-   Graphviz documentation: https://graphviz.org/documentation/
-   `asyncua` Python library: https://github.com/FreeOpcUa/opcua-asyncio

Add complete bibliographic references to the final report and cite
sources where their technical content is used.

## 12. Data and Security Notice

Before pushing files to a public GitHub repository:

-   Remove passwords, private keys, and certificates containing private
    material.
-   Check PCAP files for credentials, sensitive endpoint information,
    and confidential data.
-   Review logs and configuration files for secrets.
-   Confirm permission to publish captures and project material.
-   Consider Git LFS or an external research-data repository for large
    PCAP files.
-   Do not commit virtual environments, caches, or temporary files that
    can be recreated.

## 13. Project Status

Update this checklist as implementation progresses.

-   [x] OPC UA test environment established
-   [x] Active-learning harness developed
-   [x] AALpy integration explored
-   [x] Active model visualisation generated
-   [x] Wireshark traffic analysis performed
-   [ ] Fully documented PCAP-to-message extraction pipeline
-   [ ] Message abstraction derived and documented from PCAP
-   [ ] Passive state-machine inference from recorded traces
-   [ ] Held-out trace validation of passive model
-   [ ] Comparison of passive and active models
-   [ ] Final reproducibility and security review

------------------------------------------------------------------------

**Author:** Altaf Ahmad\
**Project:** Protocol Inference and State Machine Learning of the OPC UA
Protocol from Network Traces\
**Institution:** Hochschule Emden/Leer
