# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Provides an attacker model."""

from snram.topology import NetworkTopology
from snram.risk_score import THREAT_MAX, THREAT_INC


class Attacker:
    """Class providing attacker model."""
    def __init__(self, topology, budget=3):
        self._topology = None
        if isinstance(topology, NetworkTopology):
            self._topology = topology
        elif isinstance(topology, str): # filename is provided
            self._topology = NetworkTopology(topology)
        else:
            raise AttributeError("unknown topology provided")
        self._budget = budget

    def _increase_arc_threat(self):
        # Increase threat for the most critical arc.
        idx, t_old = self._topology.find_critical_asset(
            self._topology.get_arc_data(), "threat")
        t_new = t_old + THREAT_INC
        threat = self._topology.get_arc_data()["threat"]
        if t_new > THREAT_MAX: # threat cannot be increased above THREAT_MAX
            threat[idx] = THREAT_MAX
        else:
            threat[idx] = t_new
        self._topology.set_arc_data("threat", threat)
        return (idx, t_old, t_new)

    def _find_attackable_arcs(self):
        # Find attackable arcs and attack weights from threat x vulnerability:
        threat = self._topology.get_arc_data()["threat"]
        vuln = self._topology.get_arc_data()["vulnerability"]
        threat_vuln = threat * vuln
        arcs = []
        weights = []
        for idx, row in self._topology.get_arc_data().iterrows():
            if row["attackable"] == 1:
                arcs.append(idx)
                weights.append(threat_vuln[idx])
        return (arcs, weights)

    def maximise_threat(self):
        """Maximise threat by exploiting vulnerabilities given budget
        constraint."""
        res = []
        for _ in range(self._budget):
            # Increase threat for most critical arc:
            idx, t_old, t_new = self._increase_arc_threat()

            # Compute sum of risks:
            r_sum = self._topology.get_arc_data()["risk"].sum()
            res.append([idx, t_old, t_new, r_sum])
        return (res, self._topology)

    def threat(self):
        """Run attacker model in threat mode."""
        res, self._topology = self.maximise_threat()
        print()
        print("======================================================================")
        print("                                                                      ")
        print("                        Attacker: Threat Mode                         ")
        print("                                                                      ")
        print("======================================================================")
        print()
        print("Maximise Threat by Exploiting Arc Vulnerabilities:")
        print("%s" % ("-" * 70))
        print("#\tLink\t\tT(before)\tT(after)\tR_sum")
        print("%s" % ("-" * 70))
        for it in range(self._budget):
            sij = "(" + str(res[it][0][0]) + ", " + str(res[it][0][1]) + ")"
            print("%d\t%-12s\t%d\t\t%d\t\t%d" %
                  (it, sij, res[it][1], res[it][2], res[it][3]))
        print("%s" % ("-" * 70))
        self._topology.print()
        self._topology.critical_asset_analysis()
        return self._topology
