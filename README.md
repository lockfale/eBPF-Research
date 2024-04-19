# eBPF-Research
Code for eBPF things



### Rust things

If you're using Rust Analyzer with VS Code, add the following bit to your workspace settings.json
```
    "rust-analyzer.cargo.buildScripts.overrideCommand": null,
    "rust-analyzer.linkedProjects": [
        "monitoring/rust-monitor/Cargo.toml"
    ],
```