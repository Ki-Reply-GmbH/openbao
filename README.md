# ApeiroRA OpenBao Sync

Based on https://github.com/openbao/openbao

# Repository Structure
## Branches

**sync**: Contains all workflows and file changes from SAP perspective.

**openbao-main**: mirror of _main_ branch of https://github.com/openbao/openbao -> identical history. Please don't make any commits to the _openbao-main_ branch since it's history must not be changed! Any Pull Request into this branch should use the _rebase_ option.

**merged**: A merge of the branches _sync_ and _openbao-main_. Set as default branch so that the Hyperspace Pipelines work as expected. If possible, please don't make changes to this branch directly. Push changes first to _sync_ and after that to _merged_.

**openbao-main-updates:** Support branch created by workflows for pull requests into _openbao-main_ or _merged_.


