# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Provides an attacker model."""

from copy import deepcopy
from itertools import count
from snram.topology import NetworkTopology
from snram.network_risk import NetworkRisk
from snram.risk_score import THREAT_MAX, THREAT_INC


class Attacker:
    """Class providing attacker model."""

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

    def _increase_asset_threat(self, asset):
        # Increase threat for the asset that gives largest relative increase
        # in risk.
        #
        # Note: We could also increase the threat for the asset that gives
        # the largest absolute increase in risk.
        assert asset == "nodes" or asset == "links"
        threat_old = self.network_risk.get_threat(asset)
        vuln = self.network_risk.get_vulnerability(asset)
        cons = self.network_risk.get_consequence(asset)
        risk_old = self.network_risk.get_risk(asset)

        # Brute force; is there a faster way?
        threat_new = deepcopy(threat_old)
        threat_tmp = deepcopy(threat_old)
        for i, threat in enumerate(threat_tmp):
            threat_tmp[i] = threat + THREAT_INC
            if threat_tmp[i] > THREAT_MAX:
                threat_tmp[i] = THREAT_MAX

        risk_new = self.network_risk.compute_risk(threat_tmp, vuln, cons)
        indx = 0
        delta_risk_max = 0
        for i, r_new, r_old in zip(count(), risk_new, risk_old):
            delta_risk = (r_new - r_old) / r_old
            if delta_risk > delta_risk_max:
                indx = i
                delta_risk_max = delta_risk
        threat_new[indx] = threat_tmp[indx]
        # Ugly hack:
        # Need to store returned result in res before set_threat() is called.
        # Otherwise threat_old[indx] == threat_new[indx], which is strange ...
        # It would be more elegant to do:
        #   return (indx, threat_old[indx], threat_new[indx])
        # after calling set_threat().
        # TODO: Should look more into what is causing this behaviour.
        res = (indx, threat_old[indx], threat_new[indx])
        self.network_risk.set_threat(asset, threat_new)
        return res

    def _find_attackable_assets(self, asset):
        # Find attackable assets and attack weights from threat x vulnerability:
        assert asset == "nodes" or asset == "links"
        threat = self.network_risk.get_threat(asset)
        vuln = self.network_risk.get_vulnerability(asset)
        threat_vuln = threat * vuln
        attackable_assets = []
        attack_weights = []
        asset_data = self.network_risk.topology.node_data
        if asset == "links":
            asset_data = self.network_risk.topology.link_data
        for idx, row in asset_data.iterrows():
            if row["attackable"] == 1:
                attackable_assets.append(idx)
                attack_weights.append(threat_vuln[idx])
        return (attackable_assets, attack_weights)

    def maximise_threat(self, asset):
        """Maximise threat for given asset given budget constraint."""
        assert asset == "nodes" or asset == "links"
        res = []
        for _ in range(self.budget):
            # Increase threat for given asset:
            idx, threat_old, threat_new = self._increase_asset_threat(asset)

            # Compute sum of risks:
            risk_sum = self.network_risk.get_risk(asset).sum()
            res.append([idx, threat_old, threat_new, risk_sum])
        return (res, self.network_risk.topology)

    def threat(self):
        """Run attacker model in threat mode."""
        print()
        print("======================================================================")
        print("                                                                      ")
        print("                        Attacker: Threat Mode                         ")
        print("                                                                      ")
        print("======================================================================")
        print()

        # Attack nodes:
        res, self.network_risk.topology = self.maximise_threat("nodes")
        node_set = self.network_risk.topology.node_set
        print("Maximise Threat by Exploiting Node Vulnerabilities:")
        print("%s" % ("-" * 70))
        print("#\tNode\t\tT(before)\tT(after)\tR_sum")
        print("%s" % ("-" * 70))
        for i in range(self.budget):
            print("%d\t%-12s\t%d\t\t%d\t\t%d" %
                  (i, node_set[res[i][0]], res[i][1], res[i][2], res[i][3]))
        print("%s" % ("-" * 70))

        # Attack links:
        res, self.network_risk.topology = self.maximise_threat("links")
        link_set = self.network_risk.topology.link_set
        print("Maximise Threat by Exploiting Link Vulnerabilities:")
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
