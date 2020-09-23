# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""This is the driver for SNRAM."""

from snram.topology import NetworkTopology
from snram.network_risk import NetworkRisk
from snram.attacker import Attacker
from snram.defender import Defender
from snram.stackelberg import stackelberg
from snram.interdict import interdiction


def _print_header():
    """Print SNRAM header."""
    print("**********************************************************************")
    print("*                                                                    *")
    print("*         Suite of Network Risk Assessment Methods (SNRAM)           *")
    print("*                                                                    *")
    print("**********************************************************************")
    print()


def driver(xlsx_file, **kwargs):
    """Driver for SNRAM."""
    # Set input arguments:
    png_file = kwargs.get("png_file", None)
    save_xlsx = kwargs.get("save_xlsx", None)
    run_type = kwargs.get("run_type", "stackelberg")
    budget = int(kwargs.get("budget", 1))
    interdict = kwargs.get("interdict", "max-flow")
    attacks = int(kwargs.get("attacks", 0))
    solver = kwargs.get("solver", "cplex")
    max_iter = int(kwargs.get("max_iter", 10))
    tee = kwargs.get("tee", False)

    _print_header()

    # Initialise network topology:
    topology = NetworkTopology(xlsx_file)
    if png_file:
        topology.plot(png_file)

    # Conduct network risk assessment:
    network_risk = NetworkRisk(topology)
    network_risk.risk_assessment()

    # Identify critical assets:
    network_risk.critical_assets()

    if run_type == "stackelberg":
        topology = stackelberg(network_risk, budget, max_iter)
    elif run_type == "prepare":
        defender = Defender(network_risk, budget)
        topology = defender.prepare()
    elif run_type == "mitigate":
        defender = Defender(network_risk, budget)
        topology = defender.mitigate()
    elif run_type == "threat":
        attacker = Attacker(network_risk, budget)
        topology = attacker.threat()
    elif run_type == "interdict":
        interdiction(topology, interdict, attacks, solver, tee)

    if save_xlsx:
        topology.to_excel(save_xlsx)
