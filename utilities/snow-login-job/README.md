# SNOW Dev Instance Keep-Alive - A.K.A. "SNOW Poke"

![System Diagram](./blueprint.jpg)

## What

Trivial python script that logs into dev portal every 24 hours using creds from ESO.


## Why

Our Kargo Demo uses a developer instance of SNOW to open/move change tickets.  These instances hibernate if there is not activity in the dev portal that created it. Activity in actual snow instance does not count.



## SNOW Demo Instance Setup

To remove pain of SNOW workflow, we make some modifications.

1) delete assess stage via CHange MOdel for Normal Change
  - requires the New-->Asssess transition deleted first
2) Set authorize as initial state via Change Model
3) Set a Flow Designer flow that moves Schedule requests to Implement state.
  - Trigger - record updated, state is scheduled
  - Action - update record, state is implement
