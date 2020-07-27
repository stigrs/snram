# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Wrapper for solving network interdiction problems."""

from snram.max_flow_interdict import MaxFlowInterdiction
from snram.min_cost_flow_interdict import MinCostFlowInterdiction
from snram.sp_interdict import SPInterdiction


def interdiction(topology, method, attacks=0, solver="cplex", tee=False):
    """Solver for network interdiction problems."""
    if method == "max-flow":
        print("======================================================================")
        print("                                                                      ")
        print("                        Max Flow Interdiction                         ")
        print("                                                                      ")
        print("======================================================================")
        for it in range(attacks + 1):
            print()
            model = MaxFlowInterdiction(topology, it, solver, tee)
            model.solve()
            model.print()
    elif method == "min-cost-flow":
        print("======================================================================")
        print("                                                                      ")
        print("                      Min-Cost-Flow Interdiction                      ")
        print("                                                                      ")
        print("======================================================================")
        for it in range(attacks + 1):
            print()
            model = MinCostFlowInterdiction(topology, it, solver, tee)
            model.solve()
            model.print()
    elif method == "shortest-path":
        print("======================================================================")
        print("                                                                      ")
        print("                      Shortest Path Interdiction                      ")
        print("                                                                      ")
        print("======================================================================")
        for it in range(attacks + 1):
            print()
            model = SPInterdiction(topology, it, solver, tee)
            model.solve()
            model.print()
