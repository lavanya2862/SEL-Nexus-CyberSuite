"""The fix loop: plan -> approve -> fix on the lab VMs -> verify with Defender.

  plan.py       what to update/remove on which computer (Defender data + the allow-list config/fix_catalog.csv)
  state.py      approvals and results in data/fix/state.json (shared by the website, the CLI and the pipeline)
  executors.py  the "hands": Azure Run Command and Defender Live Response
  runner.py     runs approved fixes and judges the result the computer reports back

Safety: nothing runs without an approval; the commands come only from the catalogue (never from the AI or a
feed); Run Command only touches VMs in FIX_RESOURCE_GROUP.
"""
