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
    def __init__(self, topology):
        self._topology = None
        if isinstance(topology, NetworkTopology):
            self._topology = topology
        elif isinstance(topology, str): # filename is provided
            self._topology = NetworkTopology(topology)
        else:
            raise AttributeError("unknown topology provided")

    def _alpha(self, asset):
        """Compute alpha value for increasing threat."""
        alpha = np.zeros(len(asset))
        for i in range(len(alpha)):
            alpha[i] = -np.log(1.0 - asset["t_inf"][i] / asset["t_init"][i]) / \
                asset["a_cost"][i]
        return alpha

    def _gamma(self, asset):
        """Compute gamma value for reducing vulnerability."""
        gamma = np.zeros(len(asset))
        for i in range(len(gamma)):
            gamma[i] = -np.log(asset["v_inf"] / asset["v_init"][i]) / \
                asset["p_cost"][i]
        return gamma

    def node_degree_centrality(self):
        """Compute normalised degree centrality for the nodes."""
        graph = self._topology.get_graph_with_attackable_nodes()
        degree = list(nx.degree_centrality(graph).values())
        degree /= np.max(degree)
        return degree

    def arc_betweenness_centrality(self):
        """Compute normalised arc betweenness centrality."""
        graph = self._topology.get_graph_with_attackable_nodes()
        betweenness = list(nx.edge_betweenness_centrality(graph).values())
        betweenness /= np.max(betweenness)
        return betweenness

    def threat(self, threat_cost):
        """Compute threat function defining the probability of an attack."""
        nodes = self._topology.get_node_data()
        arcs = self._topology.get_arc_data()
        threat = []
        for i, ai in enumerate(self._alpha(nodes)):
            threat.append(1.0 - np.exp(-ai * threat_cost[i]))
        for i, ai in enumerate(self._alpha(arcs)):
            threat.append(1.0 - np.exp(-ai * threat_cost[len(nodes) + i]))
        return threat

    def vulnerability(self, vuln_cost):
        """Compute vulnerability function defining the probability of 
        destruction if attacked."""
        nodes = self._topology.get_node_data()
        arcs = self._topology.get_arc_data()
        vuln = []
        for i, vi in enumerate(self._gamma(nodes)):
