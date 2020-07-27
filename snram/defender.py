# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Provides a defender model."""

from snram.topology import NetworkTopology
from snram.risk_score import VULN_MIN, VULN_INC, CONS_MIN, CONS_INC


class Defender:
    """Class providing defender model."""
    def __init__(self, topology, budget=3):
        self._topology = None
        if isinstance(topology, NetworkTopology):
            self._topology = topology
        elif isinstance(topology, str): # filename is provided
            self._topology = NetworkTopology(topology)
        else:
            raise AttributeError("unknown topology provided")
        self._budget = budget

    def _reduce_arc_vulnerability(self):
        # Reduce vulnerability for the most critical arc.
        idx, v_old = self._topology.find_critical_asset(
            self._topology.get_arc_data(), "vulnerability")
        v_new = v_old - VULN_INC
        vuln = self._topology.get_arc_data()["vulnerability"]
        if v_new < VULN_MIN: # vulnerability cannot be reduced below VULN_MIN
            vuln[idx] = VULN_MIN
        else:
            vuln[idx] = v_new
        self._topology.set_arc_data("vulnerability", vuln)
        return (idx, v_old, v_new)

    def _reduce_arc_consequence(self):
        # Reduce consequence for the most critical arc.
        idx, c_old = self._topology.find_critical_asset(
            self._topology.get_arc_data(), "consequence")
        c_new = c_old - CONS_INC
        cons = self._topology.get_arc_data()["consequence"]
        if c_new < CONS_MIN: # consequence cannot be reduced below CONS_MIN
            cons[idx] = CONS_MIN
        else:
            cons[idx] = c_new
        self._topology.set_arc_data("consequence", cons)
        return (idx, c_old, c_new)

    def minimise_vulnerability(self):
        """Minimise vulnerabilities given budget constraint."""
        res = []
        for _ in range(self._budget):
            # Reduce vulnerability for most critical arc:
            idx, v_old, v_new = self._reduce_arc_vulnerability()

            # Compute sum of risks:
            r_sum = self._topology.get_arc_data()["risk"].sum()
            res.append([idx, v_old, v_new, r_sum])
        return (res, self._topology)

    def minimise_consequence(self):
        """Minimise consequences given budget constraint."""
        res = []
        for _ in range(self._budget):
            # Reduce consequence for most critical arc:
            idx, c_old, c_new = self._reduce_arc_consequence()

            # Compute sum of risks:
            r_sum = self._topology.get_arc_data()["risk"].sum()
            res.append([idx, c_old, c_new, r_sum])
        return (res, self._topology)

    def prepare(self):
        """Run defender model in preparedness mode (reduce vulnerabilities)."""
        res, self._topology = self.minimise_vulnerability()
        print()
        print("======================================================================")
        print("                                                                      ")
        print("                     Defender: Preparedness Mode                      ")
        print("                                                                      ")
        print("======================================================================")
        print()
        print("Arc Vulnerability Reduction:")
        print("%s" % ("-" * 70))
        print("#\tArc\t\tV(before)\tV(after)\tR_sum")
        print("%s" % ("-" * 70))
        for it in range(self._budget):
            sij = "(" + str(res[it][0][0]) + ", " + str(res[it][0][1]) + ")"
            print("%d\t%-12s\t%d\t\t%d\t\t%d" %
                  (it, sij, res[it][1], res[it][2], res[it][3]))
        print("%s" % ("-" * 70))
        self._topology.print()
        self._topology.critical_asset_analysis()
        return self._topology

    def mitigate(self):
        """Run defender model in mitigation mode (reduce consequences)."""
        res, self._topology = self.minimise_consequence()
        print()
        print("======================================================================")
        print("                                                                      ")
        print("                       Defender: Mitigation Mode                      ")
        print("                                                                      ")
        print("======================================================================")
        print()
        print("Arc Consequence Mitigation:")
        print("%s" % ("-" * 70))
        print("#\tArc\t\tC(before)\tC(after)\tR_sum")
        print("%s" % ("-" * 70))
        for it in range(self._budget):
            sij = "(" + str(res[it][0][0]) + ", " + str(res[it][0][1]) + ")"
            print("%d\t%-12s\t%d\t\t%d\t\t%d" %
                  (it, sij, res[it][1], res[it][2], res[it][3]))
        print("%s" % ("-" * 70))
        self._topology.print()
        self._topology.critical_asset_analysis()
        return self._topology
