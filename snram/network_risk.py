# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http:/

"""Provides a network risk model."""

import numpy as np
import networkx as nx
from snram.topology import NetworkTopology


class NetworkRisk:
    """Class for handling network risks. The class implements the network
    risk method that is presented in:

    - Lewis, T. G. (2019). Critical Infrastructure Protection in Homeland
      Security: Defending a Networked Nation (3rd edn.). Wiley.
    - Al Mannai, W. I. (2008). Development of a decision support tool to
      inform resource allocation for critical infrastructure protection in
      homeland security (Ph.D. thesis). Naval Postgraduate School, Monterey,
      California.
    - Al Mannai, W. I. & Lewis, T. G. (2008). A general defender-attacker
      risk model for networks. Journal of Risk Finance, 9, 244-261.
    """
    def __init__(self, topology, prevent_budget, response_budget, attack_budget):
        self._topology = None
        if isinstance(topology, NetworkTopology):
            self._topology = topology
        elif isinstance(topology, str): # filename is provided
            self._topology = NetworkTopology(topology)
        else:
            raise AttributeError("unknown topology provided")

        self._prevent_budget = prevent_budget
        self._response_budget = response_budget
        self._attack_budget = attack_budget

        self._nodes = self._topology.get_node_data()
        self._arcs = self._topology.get_arc_data()

        self._attack_cost = np.zeros(len(self._nodes) + len(self._arcs))
        self._prevent_cost = np.zeros(len(self._nodes) + len(self._arcs))
        self._response_cost = np.zeros(len(self._nodes) + len(self._arcs))

    def _alpha(self, asset):
        """Compute alpha value for increasing threat."""
        alpha = np.zeros(len(asset))
        for i in range(len(alpha)):
            alpha[i] = -np.log(1.0 - asset["t_inf"][i]) / asset["a_inf"][i]
        return alpha

    def _gamma(self, asset):
        """Compute gamma value for reducing vulnerability."""
        gamma = np.zeros(len(asset))
        for i in range(len(gamma)):
            gamma[i] = -np.log(asset["v_inf"] / asset["v_init"][i]) / \
                asset["p_inf"][i]
        return gamma

    def _beta(self, asset):
        """Compute beta value for reducing consequences."""
        beta = np.zeros(len(asset))
        for i in range(len(beta)):
            beta[i] = -np.log(asset["c_inf"] / asset["c_init"][i]) / \
                asset["r_inf"][i]
        return beta

    def _compute_lambda_threat(self):
        """Compute Lagrange multiplier for threat allocation."""
        vuln = self.vulnerability(self._prevent_cost)
        cons = self.consequence(self._response_cost)
        g_node = self._topology.node_degree_centrality()
        g_arc = self._topology.arc_betweenness_centrality()
        a_node = self._alpha(self._nodes)
        a_arc = self._alpha(self._arcs)

        n = len(self._nodes)
        m = len(self._arcs)

        t_sum = 0.0
        for i in range(n):
            t_sum += np.log(g_node[i] * vuln[i] * cons[i]) / a_node[i]
        for i in range(m):
            t_sum += np.log(g_arc[i] * vuln[n + i] * cons[n + i]) / a_arc[i]

        a_inv = 0.0
        for i in range(n):
            a_inv += 1.0 / a_node[i]
        for i in range(m):
            a_inv += 1.0 / a_arc[i]

        return (t_sum - self._attack_budget) / a_inv
    
    def _compute_lambda_prevent(self):
        """Compute Lagrange multiplier for prevent allocation."""
        vuln = self.vulnerability(self._prevent_cost)
        cons = self.consequence(self._response_cost)
        g_node = self._topology.node_degree_centrality()
        g_arc = self._topology.arc_betweenness_centrality()
        

    def _compute_attack_cost(self):
        """Compute attack allocation cost."""
        vuln = self.vulnerability(self._prevent_cost)
        cons = self.consequence(self._response_cost)
        g_node = self._topology.node_degree_centrality()
        g_arc = self._topology.arc_betweenness_centrality()
        a_node = self._alpha(self._nodes)
        a_arc = self._alpha(self._arcs)

        n = len(self._nodes)
        m = len(self._arcs)

        lambda_t = self._compute_lambda_threat()

        for i in range(n):
            self._attack_cost[i] = (
                np.log(g_node[i] * vuln[i] * cons[i]) - lambda_t) / a_node[i]
        for i in range(m):
            self._attack_cost[n + i] = (
                np.log(g_arc[i] * vuln[n + i] * cons[n + i]) - lambda_t) / a_arc[i]

        return self._attack_cost

    def threat(self, attack_cost):
        """Compute threat function defining the probability of an attack."""
        threat = []
        for i, ai in enumerate(self._alpha(self._nodes)):
            if self._nodes["attackable"][i] == 1:
                threat.append(1.0 - np.exp(-ai * attack_cost[i]))
            else:
                threat.append(0)
        for i, ai in enumerate(self._alpha(self._arcs)):
            if self._arcs["attackable"][i] == 1:
                threat.append(
                    1.0 - np.exp(-ai * attack_cost[len(self._nodes) + i]))
            else:
                threat.append(0)
        return threat

    def vulnerability(self, prevent_cost):
        """Compute vulnerability function defining the probability of 
        destruction if attacked."""
        vuln = []
        for i, gi in enumerate(self._gamma(self._nodes)):
            if self._nodes["attackable"][i] == 1:
                vuln.append(self._nodes=["v_init"][i] * np.exp(-gi * prevent_cost[i]))
            else:
                vuln.append(0)
        for i, gi in enumerate(self._gamma(self._arcs)):
            if self._arcs["attackable"][i] == 1:
                vuln.append(self._arcs["v_init"][i] *
                            np.exp(-gi * prevent_cost[len(self._nodes) + i]))
            else:
                vuln.append(0)
        return vuln

    def consequence(self, response_cost):
        """Compute consequence function defining damages from a successful
        attack."""
        cons = []
        for i, bi in enumerate(self._beta(self._nodes)):
            if self._nodes["attackable"][i] == 1:
                cons.append(self._nodes["c_init"][i] *
                            np.exp(-bi * response_cost[i]))
            else:
                cons.append(0)
        for i, bi in enumerate(self._gamma(self._arcs)):
            if self._arcs["attackable"][i] == 1:
                cons.append(self._arcs["c_init"][i] *
                            np.exp(-bi * response_cost[len(self._nodes) + i]))
            else:
                cons.append(0)
        return cons
