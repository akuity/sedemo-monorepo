# gatekeeper-app

Trivial static app used by the `gatekeeper-stage` demo in `sedemo-platform`.
It has no behavior of its own — its only purpose is to be an image tagged
by git commit SHA, so a Kargo `gate` Stage can verify a matching image
exists before promoting a Freight built from that commit.

See `sedemo-platform/apps/gatekeeper-stage/README.md` for the full demo
story and how to run it.
