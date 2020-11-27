# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Provides risk scores."""

# Threat Score:
# -------------
# 1 = very low
# 2 = low
# 3 = medium
# 4 = high
# 5 = very high
#
THREAT_MIN = 1
THREAT_MAX = 5
THREAT_INC = 1

# Vulnerability Score:
# --------------------
# 1 = very low
# 2 = low
# 3 = medium
# 4 = high
# 5 = critical
#
VULN_MIN = 1
VULN_MAX = 5
VULN_INC = 1

# Consequence Score:
# ------------------
# 1 = negligble
# 2 = minor
# 3 = moderate
# 4 = severe
# 5 = catastrophic
#
CONS_MIN = 1
CONS_MAX = 5
CONS_INC = 1

# Risk Score:
# -----------
#
RISK_MIN = 1
RISK_MAX = THREAT_MAX * VULN_MAX * CONS_MAX
RISK_INC = 1
