# PowerShell Sanctum Sanctorum

## Purpose
This is a collection of useful PowerShell scripts. This is also a learning ground for PowerShell. As more advanced techniques and best practices are learned, the scripts will evolve. Also, note that some of the scripts are bare bones, with no comments, error handling, logging, or advanced methods. These scripts were usually created because of an urgent need and there wasn't any bandwidth to flesh them out. Over time, I will glance over these scripts and make them more robust, if necessary. Anything in the `sandbox/` directory or marked as test\sample in the filename are works in progress or just testing grounds for new concepts. They are not guaranteed to work or actually do anything.

## Repository Structure
| Directory | Contents |
| --- | --- |
| `scripts/` | Production standalone scripts, grouped by domain: `imaging/`, `software/`, `domain-join/`, `autologon/`, `hardware/`, `logging/`, `utilities/`. |
| `projects/` | Self-contained, multi-file bundles that include their own helper scripts and binaries: `pc-refresh/`, `digital-signage/`, `general-autologon/`, `ramsprint/`, `tbb/`. |
| `modules/` | Reusable PowerShell modules (`.psm1`). |
| `examples/` | Learning material and samples (`gui/`, `practice/`). |
| `sandbox/` | Works in progress / experiments. Not guaranteed to work. |
| `docs/` | Instructions, notes, and assets. |

## Versioning
Whenever a script(s) get updated, we'll increase the minor release version by 1. Hopefully, this will help to archive working scripts, if the updated script isn't tested and doesn't work for some reason. Moving forward, we'll also be using development branches for updating scripts. That way we can update and test a script before the changes are merged to the main branch. Structural changes to the repository will increase the major release version by 1.

#### tl;dr
There shouldn't be any broken scripts in the main branch and if there is, check a known good release version. Also, regardless of the release version, scripts in the Scripts-Dev directory or with test\sample in the filename, aren't guaranteed to work or do anything.
