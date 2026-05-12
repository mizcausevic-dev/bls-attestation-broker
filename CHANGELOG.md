# Changelog

All notable changes to this project are documented here.

## [1.0.0] - 2026-05-12

### Released
- Published **bls-attestation-broker** as a public, portfolio-grade system focused on platform governance.
- Packaged the current implementation, documentation, validation flow, and proof surfaces into a repo that can be reviewed by technical and operating stakeholders.
- Clarified the core problem the project is addressing: policy drift, observability blind spots, and fragmented evidence during incident or review pressure.

### Why this mattered
- Existing approaches in SIEMs, monitoring platforms, governance workflows, and static policy tools were useful for parts of the workflow.
- They still left out a cleaner operator view tying evidence, control posture, and next action together.
- This release made the repo read like an operational capability rather than a narrow technical demo.

## [0.1.0] - 2026-01-15

### Shipped
- Cut the first coherent internal version of **bls-attestation-broker** with stable domain objects, review surfaces, and decision outputs.
- Established the first reviewable version of the architecture described as: Multi-signer attestation broker using BLS12-381 aggregate signatures. N signatures collapse into one 96-byte aggregate verifiable in two pairings. Reference impl with textbook BLS; production should use blst.
- Focused the repo around actionability instead of passive reporting.

## [Prototype] - 2025-02-10

### Built
- Built the first runnable prototype for the repo's main workflow and decision model.
- Validated the concept against pressure points such as policy drift, observability blind spots, latency pressure, and fragmented control evidence.
- Used the prototype phase to test whether the project could drive action, not just present information.

## [Design Phase] - 2022-07-06

### Designed
- Defined the system around operator-first and decision-legible outputs.
- Chose interfaces and examples that made sense for platform, security, reliability, and governance teams.
- Avoided reducing the project to a generic dashboard, CRUD app, or fashionable wrapper around the stack.

## [Idea Origin] - 2022-01-06

### Observed
- The original idea surfaced while looking at how teams were handling policy drift, observability blind spots, and fragmented evidence during incident or review pressure.
- The recurring pattern was that teams had data and tools, but still lacked a usable operating layer for the hardest decisions.

## [Background Signals] - 2022-08-09

### Context
- Earlier platform, governance, and operator-tooling work made one pattern hard to ignore: the systems that create the most drag are often the ones with partial controls and weak operational coherence, not the ones with no controls at all.
- That pattern shaped the thinking behind this repo well before the public version existed.