# Third-Party Notices

This repository is an independently maintained derivative work. The overall
project license remains the GNU Affero General Public License v3.0 because the
codebase derives from `yujincheng08/rust-iptv-proxy`.

## Project-Level License

- Project: `iptv-rs`
- Effective project license: `AGPL-3.0-only`
- Basis: derivative of `yujincheng08/rust-iptv-proxy`

## Referenced Upstream Projects

### 1. rozhuk-im/msd_lite

- Repository: <https://github.com/rozhuk-im/msd_lite>
- Copyright: Copyright (c) 2011 - 2021 Rozhuk Ivan <rozhuk.im@gmail.com>
- License: BSD-2-Clause
- Notes: This project informed the multicast/HTTP forwarding and ring-buffer
  style design direction.
- Retained license text: `licenses/BSD-2-Clause-msd_lite.txt`

### 2. yujincheng08/rust-iptv-proxy

- Repository: <https://github.com/yujincheng08/rust-iptv-proxy>
- Copyright: Copyright (C) 2022 yujincheng08
- License: GNU Affero General Public License v3.0
- Notes: This repository is the primary upstream base of `iptv-rs`.
- Retained project license text: `LICENSE`

### 3. yujincheng08/retina

- Repository: <https://github.com/yujincheng08/retina>
- Copyright: Copyright (c) 2021 Scott Lamb <slamb@slamb.org>
- License metadata: `MIT/Apache-2.0`
- Notes: This fork was referenced during RTSP compatibility work. Its package
  metadata points to the same dual-license model as upstream `scottlamb/retina`.
- Retained license texts:
  - `licenses/MIT-retina.txt`
  - `licenses/Apache-2.0-retina.txt`

### 4. scottlamb/retina

- Repository: <https://github.com/scottlamb/retina>
- Copyright: Copyright (c) 2021 Scott Lamb <slamb@slamb.org>
- License: `MIT OR Apache-2.0`
- Notes: RTSP session, redirect, SDP, and keepalive behavior were studied
  against this upstream implementation and its licensing terms are preserved
  here.
- Retained license texts:
  - `licenses/MIT-retina.txt`
  - `licenses/Apache-2.0-retina.txt`

## Compatibility Summary

- `yujincheng08/rust-iptv-proxy` imposes AGPLv3 obligations on this derivative
  project, so the combined work remains under AGPLv3.
- BSD-2-Clause, MIT, and Apache-2.0 notices are preserved as third-party
  attribution and license text retention requirements.
