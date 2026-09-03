"""Post-cutoff CVE collection pipeline (GHSA discovery through PF-1).

Reproduces the held-out post-cutoff set used in the paper: advisories published
after the model knowledge cutoff are taken through the CVEPath study-design
stages CS-1, CS-2, PC-1, PC-2 and PF-1, and the survivors are written in
CVEPath layout. PF-2 (manual path validation) is out of scope here.

Entry point: ``scripts/collect_post_cutoff.py``.
"""
