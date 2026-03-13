# Promotable Configuration

This directory contains "promotable configuration." Changes to the files in
this directory will produce new, promotable Freight artifacts, allowing a
version at a specific git revisions to be deployed/rolled back.

During promotion, the revision-specific version specified by the Freight is
cloned an copied to the environment directories (i.e. `env/<stage>/terraform`), 
so that it is included during the terraform apply.
