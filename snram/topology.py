# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Provides a network topology model."""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from networkx import nx
from snram.risk_score import THREAT_MIN, THREAT_MAX
from snram.risk_score import VULN_MIN, VULN_MAX
from snram.risk_score import CONS_MIN, CONS_MAX


class NetworkTopology:
    """Class for representing network topologies."""
    def __init__(self, xlsx_file, calc_cap=False):
        self._node_data = None
        self._node_set = None
        self._arc_data = None
        self._arc_set = None
        self._graph = None
        self._calc_cap = calc_cap

        # Load network topology from Excel file:
        self.load(xlsx_file)

    def _create_graph(self):
        # Create graph from list of attackable nodes.
        graph = nx.Graph()
        for i, j in zip(self._arc_data["start_node"], self._arc_data["end_node"]):
            graph.add_edge(i, j)
        return graph

    def _create_subgraph(self):
        # Create subgraph from list of attackable nodes.
        nodes = []
        for node in self._node_data():
            if node["attackable"] == 1:
                nodes.append(node)
        return self._graph.subgraph(nodes)

    def _compute_node_threat(self):
        # Compute threat index from the degree centrality of the node.
        threat = list(nx.degree_centrality(self._graph).values())
        threat = threat / np.max(threat)
        threat = [int(round(ti * THREAT_MAX)) for ti in threat]
        return threat

    def _compute_arc_threat(self):
        # Compute threat index from the edge betweenness centrality.
        threat = list(nx.edge_betweenness_centrality(self._graph).values())
        threat = threat / np.max(threat)
        threat = [int(round(ti * THREAT_MAX)) for ti in threat]
        return threat

    def _compute_node_risk(self):
        # Compute node risk = threat * vulnerability * consequence.
        threat = [THREAT_MIN] * len(self._node_data)
        vuln = [VULN_MIN] * len(self._node_data)
        cons = [CONS_MIN] * len(self._node_data)
        if "threat" in self._node_data:
            threat = self._node_data["threat"]
        if "vulnerability" in self._node_data:
            vuln = self._node_data["vulnerability"]
        if "consequence" in self._node_data:
            cons = self._node_data["consequence"]
        return [t * v * c for t, v, c in zip(threat, vuln, cons)]

    def _compute_arc_risk(self):
        # Compute link risk = threat * vulnerability * consequence.
        threat = [THREAT_MIN] * len(self._arc_data)
        vuln = [VULN_MIN] * len(self._arc_data)
        cons = [CONS_MIN] * len(self._arc_data)
        if "threat" in self._node_data:
            threat = self._arc_data["threat"]
        if "vulnerability" in self._node_data:
            vuln = self._arc_data["vulnerability"]
        if "consequence" in self._node_data:
            cons = self._arc_data["consequence"]
        return [t * v * c for t, v, c in zip(threat, vuln, cons)]

    def _compute_arc_capacity(self):
        # Compute capacity for arc.
        capacity_def = THREAT_MAX * VULN_MAX * CONS_MAX  # default capacity
        capacity = [capacity_def for _ in range(len(self._arc_data))]
        if "risk" in self._arc_data:
            capacity -= self._arc_data["risk"]
        return capacity

    def get_graph(self):
        """Return graph object."""
        return self._graph

    def get_graph_with_attackable_nodes(self):
        """Return graph object with attackable nodes."""
        return self._create_subgraph()

    def get_node_data(self):
        """Return node data."""
        return self._node_data

    def get_arc_data(self):
        """Return arc data."""
        return self._arc_data

    def get_node_set(self):
        """Return node set."""
        return self._node_set

    def get_arc_set(self):
        """Return arc set."""
        return self._arc_set

    def set_node_data(self, key, value):
        """Set node data."""
        self._node_data[key] = value
        if key == "threat" or key == "vulnerability" or key == "consequence":
            self._node_data["risk"] = self._compute_node_risk()

    def set_arc_data(self, key, value):
        """Set arc data."""
        self._arc_data[key] = value
        if key == "threat" or key == "vulnerability" or key == "consequence":
            self._arc_data["risk"] = self._compute_arc_risk()
            if self._calc_cap:
                self._arc_data["capacity"] = self._compute_arc_capacity()

    def load(self, xlsx_file):
        """Load network topology from Excel file."""
        self._node_data = pd.read_excel(xlsx_file, sheet_name="nodes")
        self._arc_data = pd.read_excel(xlsx_file, sheet_name="arcs")
        self._arc_data["xbar"] = 0
        self._graph = self._create_graph()
        if "threat" not in self._node_data:
            self._node_data["threat"] = self._compute_node_threat()
        if "risk" not in self._node_data:
            self._node_data["risk"] = self._compute_node_risk()
        if "threat" not in self._arc_data:
            self._arc_data["threat"] = self._compute_arc_threat()
        if "risk" not in self._arc_data:
            self._arc_data["risk"] = self._compute_arc_risk()
        if "capacity" not in self._arc_data:
            self._arc_data["capacity"] = self._compute_arc_capacity()
        self._node_data.set_index(["node"], inplace=True)
        self._arc_data.set_index(["start_node", "end_node"], inplace=True)
        self._node_set = self._node_data.index.unique()
        self._arc_set = self._arc_data.index.unique()

    def print(self):
        """Print network topology."""
        print("Network Topology:")
        print("%s" % ("-" * 70))
        print("Node\t\tT\tV\tC\tR")
        print("%s" % ("-" * 70))
        for i, t_i, v_i, c_i, r_i in zip(self._node_set,
                                         self._node_data["threat"],
                                         self._node_data["vulnerability"],
                                         self._node_data["consequence"],
                                         self._node_data["risk"]):
            print("%-12s\t%d\t%d\t%d\t%d" % (i, t_i, v_i, c_i, r_i))
        print("%s" % ("-" * 70))

        print("%s" % ("-" * 70))
        print("Arc\t\tT\tV\tC\tR\tQ")
        print("%s" % ("-" * 70))
        for i, t_i, v_i, c_i, r_i, q_i in zip(self._arc_set,
                                              self._arc_data["threat"],
                                              self._arc_data["vulnerability"],
                                              self._arc_data["consequence"],
                                              self._arc_data["risk"],
                                              self._arc_data["capacity"]):
            s_i = "(" + str(i[0]) + ", " + str(i[1]) + ")"
            print("%-12s\t%d\t%d\t%d\t%d\t%d" % (s_i, t_i, v_i, c_i, r_i, q_i))
        print("%s" % ("-" * 70))
        print("T = Threat (1-5)")
        print("V = Vulnerability (1-5)")
        print("C = Consequence (1-5)")
        print("R = Risk (T x V x C)")
        print("Q = Capacity")

    def to_excel(self, xlsx_file):
        """Write network topology to Excel file."""
        with pd.ExcelWriter(xlsx_file) as writer:  # pylint: disable=abstract-class-instantiated
            self._node_data.to_excel(writer, sheet_name="nodes", index=False)
            self._arc_data.to_excel(writer, sheet_name="arcs", index=False)

    def plot(self, filename=None, dpi=300):
        """Plot network topology."""
        nx.draw(self._graph, with_labels=True)
        if filename:
            plt.savefig(filename, dpi=dpi)

    def node_degree_centrality(self):
        """Compute normalised degree centrality for the nodes."""
        graph = self.get_graph_with_attackable_nodes()
        degree = list(nx.degree_centrality(graph).values())
        degree /= np.max(degree)
        return degree

    def arc_betweenness_centrality(self):
        """Compute normalised arc betweenness centrality."""
        graph = self.get_graph_with_attackable_nodes()
        betweenness = list(nx.edge_betweenness_centrality(graph).values())
        betweenness /= np.max(betweenness)
        return betweenness

    def find_critical_asset(self, asset, attribute):
        """Find index and maximum value for the given asset attribute."""
        val = asset.loc[asset["attackable"] == asset["attackable"].max()]
        if attribute == "threat":
            # Asset with lowest threat and largest vulnerability has largest
            # attack desirability:
            val = val.loc[val[attribute] == val[attribute].min()]
            val = val.loc[val["vulnerability"] == val["vulnerability"].max()]
            val = val.loc[val["risk"] == val["risk"].max()]
        else:
            # Asset with largest risk is most critical:
            val = val.loc[val[attribute] == val[attribute].max()]
            val = val.loc[val["risk"] == val["risk"].max()]
        idx = val.index.values[0]
        val = val[attribute].values[0]
        return (idx, val)

    def critical_asset_analysis(self):
        """Identify critical assets."""
        print("\nCritical Assets:")
        print("%s" % ("-" * 70))
        print("                                 Index\t\tValue")
        print("%s" % ("-" * 70))

        # Analyse nodes:
        idx, val = self.find_critical_asset(self._node_data, "threat")
        print("Node with largest threat:        %s\t\t%d" % (idx, val))

        idx, val = self.find_critical_asset(self._node_data, "vulnerability")
        print("Node with largest vulnerability: %s\t\t%d" % (idx, val))

        idx, val = self.find_critical_asset(self._node_data, "consequence")
        print("Node with largest consequence:   %s\t\t%d" % (idx, val))

        idx, val = self.find_critical_asset(self._node_data, "risk")
        print("Node with largest risk:          %s\t\t%d" % (idx, val))
        print()

        # Analyse arcs:
        idx, val = self.find_critical_asset(self._arc_data, "threat")
        sij = "(" + str(idx[0]) + ", " + str(idx[1]) + ")"
        print("Arc with largest threat:         %-12s\t%d" % (sij, val))

        idx, val = self.find_critical_asset(self._arc_data, "vulnerability")
        sij = "(" + str(idx[0]) + ", " + str(idx[1]) + ")"
        print("Arc with largest vulnerability:  %-12s\t%d" % (sij, val))

        idx, val = self.find_critical_asset(self._arc_data, "consequence")
        sij = "(" + str(idx[0]) + ", " + str(idx[1]) + ")"
        print("Arc with largest consequence:    %-12s\t%d" % (sij, val))

        idx, val = self.find_critical_asset(self._arc_data, "risk")
        sij = "(" + str(idx[0]) + ", " + str(idx[1]) + ")"
        print("Arc with largest risk:           %-12s\t%d" % (sij, val))
        print("%s\n" % ("-" * 70))
