# SNOW Dev Instance Keep-Alive - A.K.A. "SNOW Poke"

![System Diagram](./blueprint.jpg)

## What

Trivial python script that logs into dev portal every 24 hours using creds from ESO.


## Why

Our Kargo Demo uses a developer instance of SNOW to open/move change tickets.  These instances hibernate if there is not activity in the dev portal that created it. Activity in actual snow instance does not count.



