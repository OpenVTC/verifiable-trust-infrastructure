### vta-service 0.14.35 — `--did-log-file` on `create-did-webvh` (#932)

`vta create-did-webvh --did-log-file <path>` writes the DID log (did.jsonl)
to a file during creation, enabling offline publishing to external hosting
(e.g. GitLab Pages) without needing the VTA to self-host the DID.

Non-interactive (`--url`) runs previously had no way to capture the log at
all — stdout is reserved for the secrets bundle, so the command only noted
where the log belonged. Interactively the flag supplies the default for the
existing "Save DID log to file" prompt.
