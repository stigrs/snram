# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Provides a Stackelberg game for risk reduction."""

from snram.attacker import Attacker
from snram.defender import Defender
from snram.network_risk import NetworkRisk
from snram.risk_score import RISK_INC


def stackelberg(topology, budget=1, max_iter=10):
    """Run Stackelberg game."""
    print()
    print("======================================================================")
    print("                                                                      ")
    print("                   Stackelberg Game: Risk Reduction                   ")
    print("                                                                      ")
    print("======================================================================")
    print()
    print("Minimise Risk - Maximise Threat for Nodes:")
    print("%s" % ("-" * 70))
    print("#\tR_sum(V)\tR_sum(C)\tR_sum(T)")
    print("%s" % ("-" * 70))

    for it in range(max_iter):
        # Minimise vulnerability:
        defender = Defender(topology, budget)
        v_res, topology = defender.minimise_vulnerability("nodes")

        # Minimise consequences:
        defender = Defender(topology, budget)
        c_res, topology = defender.minimise_consequence("nodes")

        # Maximise threat:
        attacker = Attacker(topology, budget)
        t_res, topology = attacker.maximise_threat("nodes")

        print("%d\t%d\t\t%d\t\t%d" %
              (it, v_res[-1][-1], c_res[-1][-1], t_res[-1][-1]))

        if abs(t_res[-1][-1] - c_res[-1][-1]) <= RISK_INC:
            break
    print("%s" % ("-" * 70))

    print("Minimise Risk - Maximise Threat for Links:")
    print("%s" % ("-" * 70))
    print("#\tR_sum(V)\tR_sum(C)\tR_sum(T)")
    print("%s" % ("-" * 70))

    for it in range(max_iter):
        # Minimise vulnerability:
        defender = Defender(topology, budget)
        v_res, topology = defender.minimise_vulnerability("links")

        # Minimise consequences:
        defender = Defender(topology, budget)
        c_res, topology = defender.minimise_consequence("links")

        # Maximise threat:
        attacker = Attacker(topology, budget)
        t_res, topology = attacker.maximise_threat("links")

        print("%d\t%d\t\t%d\t\t%d" %
              (it, v_res[-1][-1], c_res[-1][-1], t_res[-1][-1]))

        if abs(t_res[-1][-1] - c_res[-1][-1]) <= RISK_INC:
            break
    print("%s\n" % ("-" * 70))

    network_risk = NetworkRisk(topology)
    network_risk.risk_assessment()
    network_risk.critical_assets()
    return topology
