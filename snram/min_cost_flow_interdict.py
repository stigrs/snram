# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

# The source code is based on the PyomoGallery example max_flow_interdict.py
# provided under the following license:
#
# Copyright (c) 2015, Sandia National Laboratories
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.

"""Provides min-cost-flow interdiction model."""

import logging
import pyomo
import pyomo.opt
import pyomo.environ as pe
from snram.topology import NetworkTopology

class MinCostFlowInterdiction:
    """Class to compute min-cost-flow interdictions."""
    def __init__(self, topology, attacks=0, solver="cplex", tee=False):
        self._topology = None
        if isinstance(topology, NetworkTopology):
            self._topology = topology
        elif isinstance(topology, str): # filename is provided
            self._topology = NetworkTopology(topology)
        else:
            raise AttributeError("unknown topology provided")

        self._attacks = attacks
        self._solver = solver
        self._tee = tee

        # Compute nCmax
        self._nCmax = len(self._topology.get_node_set()) \
            * self._topology.get_arc_data()["risk"].max()

        self._primal = self._create_primal()
        self._idual = self._create_interdict_dual()

    def _create_primal(self):
        # Create the primal pyomo model.
        #
        # This is used to compute flows after interdiction. The interdiction
        # is stored in arc_data.xbar.
        model = pe.ConcreteModel()

        # Tell pyomo to read in dual-variable information from the solver:
        model.dual = pe.Suffix(direction=pe.Suffix.IMPORT)

        # Add the sets:
        model.node_set = pe.Set(initialize=self._topology.get_node_set())
        model.edge_set = pe.Set(initialize=self._topology.get_arc_set(), dimen=2)

        # Create the variables:
        model.y = pe.Var(model.edge_set, domain=pe.NonNegativeReals)
        model.UnsatSupply = pe.Var(model.node_set, domain=pe.NonNegativeReals)
        model.UnsatDemand = pe.Var(model.node_set, domain=pe.NonNegativeReals)

        # Create the objective:
        def obj_rule(model):
            return  sum((data["risk"] + data["xbar"] * (2 * self._nCmax + 1)) \
                * model.y[e] for e, data in self._topology.get_arc_data().iterrows()) \
                    + sum(self._nCmax * (model.UnsatSupply[n] + model.UnsatDemand[n]) \
                        for n, data in self._topology.get_node_data().iterrows())
        model.OBJ = pe.Objective(rule=obj_rule, sense=pe.minimize)

        # Create the constraints, one for each node:
        def flow_bal_rule(model, n):
            tmp = self._topology.get_arc_data().reset_index()
            successors = tmp.loc[tmp.start_node == n, "end_node"].values
            predecessors = tmp.loc[tmp.end_node == n, "start_node"].values
            lhs = sum(model.y[(i, n)] for i in predecessors) \
                - sum(model.y[(n, i)] for i in successors)
            imbalance = self._topology.get_node_data()["supply_demand"].get(n, 0)
            supply_node = int(imbalance < 0)
            demand_node = int(imbalance > 0)
            rhs = (imbalance + model.UnsatSupply[n] * supply_node \
                - model.UnsatDemand[n] * demand_node)
            constr = (lhs == rhs)
            if isinstance(constr, bool):
                return pe.Constraint.Skip
            return constr
        model.FlowBalance = pe.Constraint(model.node_set, rule=flow_bal_rule)

        # Capacity constraints, one for each edge:
        def capacity_rule(model, i, j):
            capacity = self._topology.get_arc_data()["capacity"].get((i, j), -1)
            if capacity < 0:
                return pe.Constraint.Skip
            return model.y[(i, j)] <= capacity
        model.Capacity = pe.Constraint(model.edge_set, rule=capacity_rule)

        # Return the model
        return model

    def _create_interdict_dual(self):
        # Create the interdiction model.
        model = pe.ConcreteModel()

        # Add the sets:
        model.node_set = pe.Set(initialize=self._topology.get_node_set())
        model.edge_set = pe.Set(initialize=self._topology.get_arc_set(), dimen=2)

        # Create the variables:
        model.rho = pe.Var(model.node_set, domain=pe.Reals)
        model.pi = pe.Var(model.edge_set, domain=pe.NonPositiveReals)
        model.x = pe.Var(model.edge_set, domain=pe.Binary)

        # Create the objective:
        def obj_rule(model):
            return  sum(data["capacity"]*model.pi[e] \
                for e, data in self._topology.get_arc_data().iterrows() if data["capacity"] >= 0) \
                        + sum(data["supply_demand"]*model.rho[n] \
                            for n, data in self._topology.get_node_data().iterrows())
        model.OBJ = pe.Objective(rule=obj_rule, sense=pe.maximize)

        # Create the constraints for y_ij:
        def edge_constraint_rule(model, i, j):
            attackable = int(self._topology.get_arc_data()["attackable"].get((i, j), 0))
            has_cap = int(self._topology.get_arc_data()["capacity"].get((i, j), -1) >= 0)
            return model.rho[j] - model.rho[i] + model.pi[(i, j)] * has_cap <= \
                self._topology.get_arc_data()["risk"].get((i, j), 0) \
                    + (2 * self._nCmax + 1) * model.x[(i, j)] * attackable
        model.DualEdgeConstraint = pe.Constraint(model.edge_set, rule=edge_constraint_rule)

        # Create constraints for the UnsatDemand variables:
        def unsat_constraint_rule(model, n):
            imbalance = self._topology.get_node_data()["supply_demand"].get(n, 0)
            supply_node = int(imbalance < 0)
            demand_node = int(imbalance > 0)
            if supply_node:
                return -model.rho[n] <= self._nCmax
            if demand_node:
                return model.rho[n] <= self._nCmax
            return pe.Constraint.Skip
        model.UnsatConstraint = pe.Constraint(model.node_set, rule=unsat_constraint_rule)

        # Create the interdiction budget constraint:
        def block_limit_rule(model):
            model.attacks = self._attacks
            return pe.summation(model.x) <= model.attacks # pylint: disable=no-member
        model.BlockLimit = pe.Constraint(rule=block_limit_rule)

        # Return the model
        return model

    def set_attacks(self, attacks):
        """Set number of attacks."""
        self._attacks = attacks

    def solve(self):
        """Solve the min-cost-flow interdiction problem."""
        solver = pyomo.opt.SolverFactory(self._solver)

        # Solve the dual first:
        self._idual.BlockLimit.construct()
        self._idual.BlockLimit._constructed = False # pylint: disable=protected-access
        del self._idual.BlockLimit._data[None]  # pylint: disable=protected-access
        self._idual.BlockLimit.reconstruct()
        self._idual.preprocess()
        results = solver.solve(self._idual, tee=self._tee)

        # Check that we actually computed an optimal solution:
        if results.solver.status != pyomo.opt.SolverStatus.ok:
            logging.warning("Solver not OK, check solver")
        if results.solver.termination_condition != pyomo.opt.TerminationCondition.optimal:
            logging.warning("Check solver optimality")

        # Now put interdictions into xbar and solve primal:
        self._idual.solutions.load_from(results)

        for e in self._topology.get_arc_data().index:
            self._topology.get_arc_data().loc[e, "xbar"] = \
                self._idual.x[e].value

        self._primal.OBJ.construct()
        self._primal.OBJ._constructed = False # pylint: disable=protected-access
        self._primal.OBJ._init_sense = pe.minimize # pylint: disable=protected-access
        del self._primal.OBJ._data[None]  # pylint: disable=protected-access
        self._primal.OBJ.reconstruct()
        self._primal.preprocess()
        results = solver.solve(self._primal, tee=self._tee)

        # Check that we actually computed an optimal solution:
        if results.solver.status != pyomo.opt.SolverStatus.ok:
            logging.warning("Solver not OK, check solver")
        if results.solver.termination_condition != pyomo.opt.TerminationCondition.optimal:
            logging.warning("Check solver optimality")

        # Load results:
        self._primal.solutions.load_from(results)

        # Return results:
        return self._primal, self._idual

    def print(self):
        """Print solution."""
        edges = sorted(self._topology.get_arc_set())
        print("%s" % ("-" * 70))
        print("Number of attacks: %d" % self._attacks)
        print("%s" % ("-" * 70))
        it = 0
        for e in edges:
            if self._idual.x[e].value > 0:
                it += 1
                eij = "(" + str(e[0]) + ", " + str(e[1]) + ")"
                print("Interdicted arc %d: %s" % (it, eij))
        nodes = sorted(self._topology.get_node_data().index)
        for n in nodes:
            remain_supply = self._primal.UnsatSupply[n].value
            if remain_supply > 0:
                print("Remaining supply on node %s: %.2f" % (str(n), remain_supply))
        for n in nodes:
            remain_demand = self._primal.UnsatDemand[n].value
            if remain_demand > 0:
                print("Remaining demand on node %s: %.2f" % (str(n), remain_demand))
        print("%s" % ("-" * 70))
        print("Arc\t\tFlow")
        print("%-12s" % ("-" * 70))
        for ei, ej in self._topology.get_arc_set():
            flow = self._primal.y[(ei, ej)].value
            eij = "(" + str(ei) + ", " + str(ej) + ")"
            print("%-12s\t%.2f" % (eij, flow))
        print("%s" % ("-" * 70))
        print("Total cost: %.2f (primal), %.2f (dual)" %
              (self._primal.OBJ(), self._idual.OBJ()))
