#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# The image carries the listener CA trust chain tlsCa names, from build time.
# Refresh it from the provider at start (a development iya-sts makes a new CA
# when it restarts), unless TLS_CA_REFRESH=0. A provider that is down, or a
# read-only mount, leaves the file as it is and the demo still starts.
if [ "${TLS_CA_REFRESH:-1}" != "0" ]; then
  python /app/scripts/trust_chain.py --config "${GNAP_CONFIG:-/app/demo/gnap.json}" || true
fi
exec "$@"
