# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http:/

"""Provides a network risk model."""

from snram.topology import NetworkTopology
from snram.risk_score import THREAT_MIN, THREAT_MAX
from snram.risk_score import VULN_MIN
from snram.risk_score import CONS_MIN


class NetworkRisk:
    """Class for handling network risks."""

    def __init__(self, topology):
        self.topology = None
        if isinstance(topology, NetworkTopology):
            self.topology = topology
        elif isinstance(topology, str):  # filename is provided
            self.topology = NetworkTopology(topology)
        else:
            raise AttributeError("unknown topology provided")

        if "threat" not in self.topology.node_data:
            self.topology.node_data["threat"] = self._compute_node_threat()
        if "risk" not in self.topology.node_data:
            self.topology.node_data["risk"] = self._compute_node_risk()
        if "threat" not in self.topology.link_data:
            self.topology.link_data["threat"] = self._compute_link_threat()
        if "risk" not in self.topology.link_data:
            self.topology.link_data["risk"] = self._compute_link_risk()

    def _compute_node_threat(self):
        """Compute threat index from the degree centrality of the node."""
        degree = self.topology.node_degree_centrality()
        return [int(round(di * THREAT_MAX)) for di in degree]

    def _compute_link_threat(self):
        """Compute threat index from the edge betweenness centrality."""
        betweenness = self.topology.link_betweenness_centrality()
        return [int(round(bi * THREAT_MAX)) for bi in betweenness]

    def _compute_node_risk(self):
        """Compute node risk = threat * vulnerability * consequence."""
        if "threat" in self.topology.node_data:
            threat = self.topology.node_data["threat"]
        else:
            threat = [THREAT_MIN] * len(self.topology.node_data)
        if "vulnerability" in self.topology.node_data:
            vuln = self.topology.node_data["vulnerability"]
        else:
            vuln = [VULN_MIN] * len(self.topology.node_data)
        if "consequence" in self.topology.node_data:
            cons = self.topology.node_data["consequence"]
        else:
            cons = [CONS_MIN] * len(self.topology.node_data)
        risk = self.compute_risk(threat, vuln, cons)
        self.topology.node_data["risk"] = risk
        return risk

    def _compute_link_risk(self):
        """Compute link risk = threat * vulnerability * consequence."""
        if "threat" in self.topology.link_data:
            threat = self.topology.link_data["threat"]
        else:
            threat = [THREAT_MIN] * len(self.topology.link_data)
        if "vulnerability" in self.topology.link_data:
            vuln = self.topology.link_data["vulnerability"]
        else:
            vuln = [VULN_MIN] * len(self.topology.link_data)
        if "consequence" in self.topology.link_data:
            cons = self.topology.link_data["consequence"]
        else:
            cons = [CONS_MIN] * len(self.topology.link_data)
        risk = self.compute_risk(threat, vuln, cons)
        self.topology.link_data["risk"] = risk
        return risk

    def get_threat(self, asset):
        """Get threat vector for given asset."""
        if asset == "nodes":
            return self.topology.node_data["threat"]
        elif asset == "links":
            return self.topology.link_data["threat"]

    def set_threat(self, asset, threat):
        """Set threat vector for given asset and update risk vector."""
        if asset == "nodes":
            assert len(self.topology.node_data["threat"]) == len(threat)
            self.topology.node_data["threat"] = threat
            self._compute_node_risk()
        elif asset == "links":
            assert len(self.topology.link_data["threat"]) == len(threat)
            self.topology.link_data["threat"] = threat
            self._compute_link_risk()

    def get_vulnerability(self, asset):
        """Get vulnerability vector for given asset."""
        if asset == "nodes":
            return self.topology.node_data["vulnerability"]
        elif asset == "links":
            return self.topology.link_data["vulnerability"]

    def set_vulnerability(self, asset, vuln):
        """Set vulnerability vector for given asset and update risk vector."""
        if asset == "nodes":
            assert len(self.topology.node_data["vulnerability"]) == len(vuln)
            self.topology.node_data["vulnerability"] = vuln
            self._compute_node_risk()
        elif asset == "links":
            assert len(self.topology.link_data["vulnerability"]) == len(vuln)
            self.topology.link_data["vulnerability"] = vuln
            self._compute_link_risk()

    def get_consequence(self, asset):
        """Get consequence vector for given asset."""
        if asset == "nodes":
            return self.topology.node_data["consequence"]
        elif asset == "links":
            return self.topology.link_data["consequence"]

    def set_consequence(self, asset, vuln):
        """Set consequence vector for given asset and update risk vector."""
        if asset == "nodes":
            assert len(self.topology.node_data["consequence"]) == len(vuln)
            self.topology.node_data["consequence"] = vuln
            self._compute_node_risk()
        elif asset == "links":
            assert len(self.topology.link_data["consequence"]) == len(vuln)
            self.topology.link_data["consequence"] = vuln
            self._compute_link_risk()

    def get_risk(self, asset):
        """Get risk vector for given asset."""
        if asset == "nodes":
            return self.topology.node_data["risk"]
        elif asset == "links":
            return self.topology.link_data["risk"]

    def compute_risk(self, threat, vuln, cons):
        """Compute risk from threat, vulnerability and consequence vectors."""
        return [t * v * c for t, v, c in zip(threat, vuln, cons)]

    def find_critical_asset(self, asset, attribute):
        """Find index and maximum value for the given asset attribute."""
        val = asset.loc[asset["attackable"] == asset["attackable"].max()]
        # Asset with largest risk is most critical:
        val = val.loc[val[attribute] == val[attribute].max()]
        val = val.loc[val["risk"] == val["risk"].max()]
        idx = val.index.values[0]
        val = val[attribute].values[0]
        return (idx, val)

    def risk_assessment(self):
        """Conduct network risk assessment."""
        print("Network Risk Assessment:")
        print("%s" % ("-" * 70))
        print("Node\t\tT\tV\tC\tR")
        print("%s" % ("-" * 70))
        for node, threat, vuln, cons, risk in zip(self.topology.node_set,
                                                  self.topology.node_data["threat"],
                                                  self.topology.node_data["vulnerability"],
                                                  self.topology.node_data["consequence"],
                                                  self.topology.node_data["risk"]):
            print("%-12s\t%d\t%d\t%d\t%d" % (node, threat, vuln, cons, risk))
        print("%s" % ("-" * 70))

        print("%s" % ("-" * 70))
        print("Link\t\tT\tV\tC\tR")
        print("%s" % ("-" * 70))
        for link, threat, vuln, cons, risk in zip(self.topology.link_set,
                                                  self.topology.link_data["threat"],
                                                  self.topology.link_data["vulnerability"],
                                                  self.topology.link_data["consequence"],
                                                  self.topology.link_data["risk"]):
            link_ij = "(" + str(link[0]) + ", " + str(link[1]) + ")"
            print("%-12s\t%d\t%d\t%d\t%d" %
                  (link_ij, threat, vuln, cons, risk))
        print("%s" % ("-" * 70))
        print("T = Threat (1-5)")
        print("V = Vulnerability (1-5)")
        print("C = Consequence (1-5)")
        print("R = Risk (T x V x C)")

    def critical_assets(self):
        """Identify critical assets."""
        print("\nCritical Assets:")
        print("%s" % ("-" * 70))
        print("                                 Index\t\tValue")
        print("%s" % ("-" * 70))

        # Analyse nodes:
        node_data = self.topology.node_data
        idx, val = self.find_critical_asset(node_data, "threat")
        print("Node with largest threat:        %s\t\t%d" % (idx, val))

        idx, val = self.find_critical_asset(node_data, "vulnerability")
        print("Node with largest vulnerability: %s\t\t%d" % (idx, val))

        idx, val = self.find_critical_asset(node_data, "consequence")
        print("Node with largest consequence:   %s\t\t%d" % (idx, val))

        idx, val = self.find_critical_asset(node_data, "risk")
        print("Node with largest risk:          %s\t\t%d" % (idx, val))
        print()

        # Analyse links:
        link_data = self.topology.link_data
        idx, val = self.find_critical_asset(link_data, "threat")
        sij = "(" + str(idx[0]) + ", " + str(idx[1]) + ")"
        print("Link with largest threat:        %-12s\t%d" % (sij, val))

        idx, val = self.find_critical_asset(link_data, "vulnerability")
        sij = "(" + str(idx[0]) + ", " + str(idx[1]) + ")"
        print("Link with largest vulnerability: %-12s\t%d" % (sij, val))

        idx, val = self.find_critical_asset(link_data, "consequence")
        sij = "(" + str(idx[0]) + ", " + str(idx[1]) + ")"
        print("Link with largest consequence:   %-12s\t%d" % (sij, val))

        idx, val = self.find_critical_asset(link_data, "risk")
        sij = "(" + str(idx[0]) + ", " + str(idx[1]) + ")"
        print("Link with largest risk:          %-12s\t%d" % (sij, val))
        print("%s" % ("-" * 70))

        art_pts = self.topology.articulation_points()
        print("Articulation points: ", end="")
        if len(art_pts) == 0 or art_pts is None:
            print("None")
        else:
            for node in art_pts:
                print("%s, " % node, end="")
            print()
        print()
