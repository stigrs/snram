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
        elif isinstance(topology, str): # filename is provided
            self.topology = NetworkTopology(topology)
        else:
            raise AttributeError("unknown topology provided")

        if "threat" not in self.topology.node_data:
            self.topology.node_data["threat"] = self._compute_node_threat()
        if "risk" not in self.topology.node_data:
            self.topology.node_data["risk"] = self._compute_node_risk()
        if "threat" not in self.topology.arc_data:
            self.topology.arc_data["threat"] = self._compute_arc_threat()
        if "risk" not in self.topology.arc_data:
            self.topology.arc_data["risk"] = self._compute_arc_risk()

    def _compute_node_threat(self):
        """Compute threat index from the degree centrality of the node."""
        degree = self.topology.node_degree_centrality()
        return [int(round(di * THREAT_MAX)) for di in degree]

    def _compute_arc_threat(self):
        """Compute threat index from the edge betweenness centrality."""
        betweenness = self.topology.arc_betweenness_centrality()
        return [int(round(bi * THREAT_MAX)) for bi in betweenness]

    def _compute_node_risk(self):
        """Compute node risk = threat * vulnerability * consequence."""
        threat = [THREAT_MIN] * len(self.topology.node_data)
        vuln = [VULN_MIN] * len(self.topology.node_data)
        cons = [CONS_MIN] * len(self.topology.node_data)
        if "threat" in self.topology.node_data:
            threat = self.topology.node_data["threat"]
        if "vulnerability" in self.topology.node_data:
            vuln = self.topology.node_data["vulnerability"]
        if "consequence" in self.topology.node_data:
            cons = self.topology.node_data["consequence"]
        return [t * v * c for t, v, c in zip(threat, vuln, cons)]

    def _compute_arc_risk(self):
        """Compute link risk = threat * vulnerability * consequence."""
        threat = [THREAT_MIN] * len(self.topology.arc_data)
        vuln = [VULN_MIN] * len(self.topology.arc_data)
        cons = [CONS_MIN] * len(self.topology.arc_data)
        if "threat" in self.topology.arc_data:
            threat = self.topology.arc_data["threat"]
        if "vulnerability" in self.topology.arc_data:
            vuln = self.topology.arc_data["vulnerability"]
        if "consequence" in self.topology.arc_data:
            cons = self.topology.arc_data["consequence"]
        return [t * v * c for t, v, c in zip(threat, vuln, cons)]

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
        print("Arc\t\tT\tV\tC\tR")
        print("%s" % ("-" * 70))
        for arc, threat, vuln, cons, risk in zip(self.topology.arc_set,
                                                 self.topology.arc_data["threat"],
                                                 self.topology.arc_data["vulnerability"],
                                                 self.topology.arc_data["consequence"],
                                                 self.topology.arc_data["risk"]):
            arc_ij = "(" + str(arc[0]) + ", " + str(arc[1]) + ")"
            print("%-12s\t%d\t%d\t%d\t%d" % (arc_ij, threat, vuln, cons, risk))
        print("%s" % ("-" * 70))
        print("T = Threat (1-5)")
        print("V = Vulnerability (1-5)")
        print("C = Consequence (1-5)")
        print("R = Risk (T x V x C)")
