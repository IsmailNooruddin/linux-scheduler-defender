"""
Top-level source package for the Linux Scheduler Defender project.

Subpackages:
  - src.attacker  : [Member A] Isolated decoy sandbox, XOR ransomware simulator, benign activity
  - src.defender  : [Member B] Lightweight inotify monitor and SIGSTOP defender
  - src.workload  : [Member C] Synthetic multi-process CPU stress workload
  - src.scheduler : [Member C] Linux scheduler / cgroup v2 wrappers and automated trial runner
  - src.analysis  : [Member D] Trial metrics aggregation and figure generation
"""
