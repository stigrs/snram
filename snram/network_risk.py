# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http:/

"""Provides a network risk model."""

import numpy as np
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
        vuln = self.vulnerability()
        cons = self.consequence()
        d_node = self._topology.node_degree_centrality()
        d_arc = self._topology.arc_betweenness_centrality()
        a_node = self._alpha(self._nodes)
        a_arc = self._alpha(self._arcs)

        n = len(self._nodes)
        m = len(self._arcs)

        t_sum = 0.0
        for i in range(n):
            t_sum += np.log(d_node[i] * vuln[i] * cons[i]) / a_node[i]
        for i in range(m):
            t_sum += np.log(d_arc[i] * vuln[n + i] * cons[n + i]) / a_arc[i]

        a_inv = 0.0
        for i in range(n):
            a_inv += 1.0 / a_node[i]
        for i in range(m):
            a_inv += 1.0 / a_arc[i]

        return (t_sum - self._attack_budget) / a_inv

    def _compute_lambda_prevent(self):
        """Compute Lagrange multiplier for prevent allocation."""
        threat = self.threat()
        cons = self.consequence()
        d_node = self._topology.node_degree_centrality()
        d_arc = self._topology.arc_betweenness_centrality()
        g_node = self._gamma(self._nodes)
        g_arc = self._gamma(self._arcs)

        n = len(self._nodes)
        m = len(self._arcs)

        p_sum = 0.0
        for i in range(n):
            p_sum += np.log(d_node[i] * threat[i] *
                            self._nodes["v_init"][i] * cons[i]) / g_node[i]
        for i in range(m):
            p_sum += np.log(d_arc[i] * threat[n + i] *
                            self._arcs["v_init"][i] * cons[n + i]) / g_arc[i]

        g_inv = 0.0
        for i in range(n):
            g_inv += 1.0 / g_node[i]
        for i in range(m):
            g_inv += 1.0 / g_arc[i]

        return (p_sum - self._prevent_budget) / g_inv

    def _compute_lambda_response(self):
        """Compute Lagrange multiplier for response allocation."""
        threat = self.threat()
        vuln = self.vulnerability()
        d_node = self._topology.node_degree_centrality()
        d_arc = self._topology.arc_betweenness_centrality()
        b_node = self._beta(self._nodes)
        b_arc = self._beta(self._arcs)

        n = len(self._nodes)
        m = len(self._arcs)

        r_sum = 0.0
        for i in range(n):
            r_sum += np.log(d_node[i] * threat[i] * vuln[i]
                            * self._nodes["c_init"][i]) / b_node[i]
        for i in range(m):
            r_sum += np.log(d_arc[i] * threat[n + i] * vuln[n + i]
                            * self._arcs["c_init"][i]) / b_arc[i]

        b_inv = 0.0
        for i in range(n):
            b_inv += 1.0 / b_node[i]
        for i in range(m):
            b_inv += 1.0 / b_arc[i]

        return (r_sum - self._response_budget) / b_inv

    def _compute_attack_cost(self):
        """Compute attack allocation cost."""
        vuln = self.vulnerability()
        cons = self.consequence()
        d_node = self._topology.node_degree_centrality()
        d_arc = self._topology.arc_betweenness_centrality()
        a_node = self._alpha(self._nodes)
        a_arc = self._alpha(self._arcs)

        n = len(self._nodes)
        m = len(self._arcs)

        lambda_t = self._compute_lambda_threat()

        for i in range(n):
            self._attack_cost[i] = (
                np.log(d_node[i] * vuln[i] * cons[i]) - lambda_t) / a_node[i]
            if self._attack_cost[i] < 0.0:
                self._attack_cost[i] = 0.0
        for i in range(m):
            self._attack_cost[n + i] = (
                np.log(d_arc[i] * vuln[n + i] * cons[n + i]) - lambda_t) / a_arc[i]
            if self._attack_cost[n + i] < 0.0:
                self._attack_cost[n + i] = 0.0

        return self._attack_cost

    def _compute_prevent_cost(self):
        """Compute prevent allocation cost."""
        threat = self.threat()
        cons = self.consequence()
        d_node = self._topology.node_degree_centrality()
        d_arc = self._topology.arc_betweenness_centrality()
        g_node = self._gamma(self._nodes)
        g_arc = self._gamma(self._arcs)

        n = len(self._nodes)
        m = len(self._arcs)

        lambda_p = self._compute_lambda_prevent()

        for i in range(n):
            self._prevent_cost[i] = (np.log(
                d_node[i] * threat[i] * self._nodes["v_init"][i] * cons[i]) - lambda_p) / g_node[i]
            if self._prevent_cost[i] < 0.0:
                self._prevent_cost[i] = 0.0
        for i in range(m):
            self._prevent_cost[n + i] = (np.log(d_arc[i] * threat[n + i] *
                                                self._arcs["v_init"][i] * cons[n + i]) - lambda_p) / g_arc[i]
            if self._prevent_cost[n + i] < 0.0:
                self._prevent_cost[n + i] = 0.0

        return self._prevent_cost

    def _compute_response_cost(self):
        """Compute response allocation cost."""
        threat = self.threat()
        vuln = self.vulnerability()
        d_node = self._topology.node_degree_centrality()
        d_arc = self._topology.arc_betweenness_centrality()
        b_node = self._beta(self._nodes)
        b_arc = self._beta(self._arcs)

        n = len(self._nodes)
        m = len(self._arcs)

        lambda_r = self._compute_lambda_response()

        for i in range(n):
            self._response_cost[i] = (np.log(
                d_node[i] * threat[i] * vuln[i] * self._nodes["c_init"][i]) - lambda_r) / b_node[i]
            if self._response_cost[i] < 0.0:
                self._response_cost[i] = 0.0
        for i in range(m):
            self._response_cost[n + i] = (np.log(d_arc[i] * threat[n + i]
                                                 * vuln[n + i] * self._arcs["c_init"][i]) - lambda_r) / b_arc[i]
            if self._response_cost[n + i] < 0.0:
                self._response_cost[n + i] = 0.0

        return self._response_cost

    def threat(self):
        """Compute threat function defining the probability of an attack."""
        threat = []
        for i, ai in enumerate(self._alpha(self._nodes)):
            if self._nodes["attackable"][i] == 1:
                threat.append(1.0 - np.exp(-ai * self._attack_cost[i]))
            else:
                threat.append(0)
        for i, ai in enumerate(self._alpha(self._arcs)):
            if self._arcs["attackable"][i] == 1:
                threat.append(
                    1.0 - np.exp(-ai * self._attack_cost[len(self._nodes) + i]))
            else:
                threat.append(0)
        return threat

    def vulnerability(self):
        """Compute vulnerability function defining the probability of
        destruction if attacked."""
        vuln = []
        for i, gi in enumerate(self._gamma(self._nodes)):
            if self._nodes["attackable"][i] == 1:
                vuln.append(self._nodes["v_init"][i] *
                            np.exp(-gi * self._prevent_cost[i]))
            else:
                vuln.append(0)
        for i, gi in enumerate(self._gamma(self._arcs)):
            if self._arcs["attackable"][i] == 1:
                vuln.append(
                    self._arcs["v_init"][i] * np.exp(-gi * self._prevent_cost[len(self._nodes) + i]))
            else:
                vuln.append(0)
        return vuln

    def consequence(self):
        """Compute consequence function defining damages from a successful
        attack."""
        cons = []
        for i, bi in enumerate(self._beta(self._nodes)):
            if self._nodes["attackable"][i] == 1:
                cons.append(self._nodes["c_init"][i] *
                            np.exp(-bi * self._response_cost[i]))
            else:
                cons.append(0)
        for i, bi in enumerate(self._gamma(self._arcs)):
            if self._arcs["attackable"][i] == 1:
                cons.append(
                    self._arcs["c_init"][i] * np.exp(-bi * self._response_cost[len(self._nodes) + i]))
            else:
                cons.append(0)
        return cons

    def risk(self):
        """Compute risk function."""
        d_node = self._topology.node_degree_centrality()
        d_arc = self._topology.arc_betweenness_centrality()
        d = d_node + d_arc
        t = self.threat()
        v = self.vulnerability()
        c = self.consequence()

        z = np.zeros(len(d))
        for i in range(len(d)):
            z[i] = d[i] * t[i] * v[i] * c[i]

        return z
