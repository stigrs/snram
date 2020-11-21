# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Provides a defender model."""

from snram.topology import NetworkTopology
from snram.network_risk import NetworkRisk
from snram.risk_score import VULN_MIN, VULN_INC, CONS_MIN, CONS_INC


class Defender:
    """Class providing defender model."""

    def __init__(self, network_risk, budget=1):
        self.network_risk = None
        if isinstance(network_risk, NetworkRisk):
            self.network_risk = network_risk
        elif isinstance(network_risk, NetworkTopology):  # topology is provided
            self.network_risk = NetworkRisk(network_risk)
        elif isinstance(network_risk, str):  # filename is provided
            self.network_risk = NetworkRisk(network_risk)
        else:
            raise AttributeError("unknown topology provided")
        self.budget = budget

    def _reduce_asset_vulnerability(self, asset):
        # Reduce vulnerability for the most critical asset.
        asset_data = None
        if asset == "nodes":
            asset_data = self.network_risk.topology.node_data
        elif asset == "links":
            asset_data = self.network_risk.topology.link_data
        idx, v_old = self.network_risk.find_critical_asset(
            asset_data, "vulnerability")
        v_new = v_old - VULN_INC
        vuln = self.network_risk.get_vulnerability(asset)
        if v_new < VULN_MIN:  # vulnerability cannot be reduced below VULN_MIN
            vuln[idx] = VULN_MIN
        else:
            vuln[idx] = v_new
        self.network_risk.set_vulnerability(asset, vuln)
        return (idx, v_old, v_new)

    def _reduce_asset_consequence(self, asset):
        # Reduce consequence for the most critical asset.
        asset_data = None
        if asset == "nodes":
            asset_data = self.network_risk.topology.node_data
        elif asset == "links":
            asset_data = self.network_risk.topology.link_data
        idx, c_old = self.network_risk.find_critical_asset(
            asset_data, "consequence")
        c_new = c_old - CONS_INC
        cons = self.network_risk.get_consequence(asset)
        if c_new < CONS_MIN:  # consequence cannot be reduced below CONS_MIN
            cons[idx] = CONS_MIN
        else:
            cons[idx] = c_new
        self.network_risk.set_consequence(asset, cons)
        return (idx, c_old, c_new)

    def minimise_vulnerability(self, asset):
        """Minimise vulnerabilities given budget constraint."""
        assert asset == "nodes" or asset == "links"
        res = []
        for _ in range(self.budget):
            # Reduce vulnerability for most critical asset:
            idx, v_old, v_new = self._reduce_asset_vulnerability(asset)

            # Compute sum of risks:
            r_sum = self.network_risk.get_risk(asset).sum()
            res.append([idx, v_old, v_new, r_sum])
        return (res, self.network_risk.topology)

    def minimise_consequence(self, asset):
        """Minimise consequences given budget constraint."""
        assert asset == "nodes" or asset == "links"
        res = []
        for _ in range(self.budget):
            # Reduce consequence for most critical asset:
            idx, c_old, c_new = self._reduce_asset_consequence(asset)

            # Compute sum of risks:
            r_sum = self.network_risk.get_risk(asset).sum()
            res.append([idx, c_old, c_new, r_sum])
        return (res, self.network_risk.topology)

    def prepare(self):
        """Run defender model in preparedness mode (reduce vulnerabilities)."""
        print()
        print("======================================================================")
        print("                                                                      ")
        print("                     Defender: Preparedness Mode                      ")
        print("                                                                      ")
        print("======================================================================")
        print()

        # Defend nodes:
        res, self.network_risk.topology = self.minimise_vulnerability("nodes")
        node_set = self.network_risk.topology.node_set
        print("Node Vulnerability Reduction:")
        print("%s" % ("-" * 70))
        print("#\tNode\t\tV(before)\tV(after)\tR_sum")
        print("%s" % ("-" * 70))
        for i in range(self.budget):
            print("%d\t%-12s\t%d\t\t%d\t\t%d" %
                  (i, node_set[res[i][0]], res[i][1], res[i][2], res[i][3]))
        print("%s" % ("-" * 70))

        # Defend links:
        res, self.network_risk.topology = self.minimise_vulnerability("links")
        link_set = self.network_risk.topology.link_set
        print("Link Vulnerability Reduction:")
        print("%s" % ("-" * 70))
        print("#\tLink\t\tT(before)\tT(after)\tR_sum")
        print("%s" % ("-" * 70))
        for i in range(self.budget):
            sij = "(" + str(link_set[res[i][0]][0]) + \
                ", " + str(link_set[res[i][0]][1]) + ")"
            print("%d\t%-12s\t%d\t\t%d\t\t%d" %
                  (i, sij, res[i][1], res[i][2], res[i][3]))
        print("%s" % ("-" * 70))

        self.network_risk.risk_assessment()
        self.network_risk.critical_assets()
        return self.network_risk.topology

    def mitigate(self):
        """Run defender model in mitigation mode (reduce consequences)."""
        print()
        print("======================================================================")
        print("                                                                      ")
        print("                       Defender: Mitigation Mode                      ")
        print("                                                                      ")
        print("======================================================================")
        print()

        # Defend nodes:
        res, self.network_risk.topology = self.minimise_consequence("nodes")
        node_set = self.network_risk.topology.node_set
        print("Node Consequence Reduction:")
        print("%s" % ("-" * 70))
        print("#\tNode\t\tV(before)\tV(after)\tR_sum")
        print("%s" % ("-" * 70))
        for i in range(self.budget):
            print("%d\t%-12s\t%d\t\t%d\t\t%d" %
                  (i, node_set[res[i][0]], res[i][1], res[i][2], res[i][3]))
        print("%s" % ("-" * 70))

        # Defend links:
        res, self.network_risk.topology = self.minimise_consequence("links")
        link_set = self.network_risk.topology.link_set
        print("Link Consequence Reduction:")
        print("%s" % ("-" * 70))
        print("#\tLink\t\tT(before)\tT(after)\tR_sum")
        print("%s" % ("-" * 70))
        for i in range(self.budget):
            sij = "(" + str(link_set[res[i][0]][0]) + \
                ", " + str(link_set[res[i][0]][1]) + ")"
            print("%d\t%-12s\t%d\t\t%d\t\t%d" %
                  (i, sij, res[i][1], res[i][2], res[i][3]))
        print("%s" % ("-" * 70))

        self.network_risk.risk_assessment()
        self.network_risk.critical_assets()
        return self.network_risk.topology
