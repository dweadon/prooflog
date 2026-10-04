# Example log

`OpenSSH_2k.log` is a real SSH server log: 2,000 lines from a server under attack, with brute-force and password-spraying attempts. The [live demo](https://dweadon.github.io/prooflog/) report was made from this exact file, so you can open it and check any line the report cites.

Try it locally:

```bash
python -m engine.detect examples/OpenSSH_2k.log      # rule-based findings, no AI needed
python -m engine.verify examples/OpenSSH_2k.log      # full pipeline (needs an API key)
```

You can also upload it in the dashboard with **Check a log file**.

## Source and credit

This file is unmodified from **[Loghub](https://github.com/logpai/loghub)** (`OpenSSH/OpenSSH_2k.log`), a collection of system log datasets by the LogPAI team. They make it freely available for research and academic work. Distributed here under those terms, with this reference to the Loghub repository:

> Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics.* IEEE International Symposium on Software Reliability Engineering (ISSRE), 2023.
