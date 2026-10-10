# doctor-core

The parts of the `doctor/1` machine-output contract that are identical across the doctor-labs
tools (ble-doctor, sim-doctor, android-doctor, ...): `Severity`, `ExitCode`, `Finding`,
`Envelope`, `Score` (shape and labels only), `sanitize`, `fingerprint` and a SARIF builder.

Not here, on purpose: each tool's score formula and its fingerprint inputs.

```toml
doctor-core = { git = "https://github.com/doctor-labs/doctor-core", tag = "v0.1.0" }
```
