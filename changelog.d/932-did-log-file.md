### vta-config 0.3.3 / vta-service 0.14.33 — `--did-log-file` on `create-did-webvh` (#932)

`vta create-did-webvh --did-log-file <path>` writes the DID log (did.jsonl)
to a file during creation, enabling offline publishing to external hosting
(e.g. GitLab Pages) without needing the VTA to self-host the DID.
