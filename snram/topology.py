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


class NetworkTopology:
    """Class for representing network topologies."""
    def __init__(self, xlsx_file):
        self.node_data = None
        self.node_set = None
        self.arc_data = None
        self.arc_set = None
        self.graph = None

        # Load network topology from Excel file:
        self.load(xlsx_file)

    def _create_graph(self):
        # Create graph from list of attackable nodes.
        graph = nx.Graph()
        #for arc, data in zip(self.arc_set, self.arc_data):
        #    graph.add_edge(arc[0], arc[1], capasity=data["capacity"])
        for arc, data in self.arc_data.iterrows():
            graph.add_edge(arc[0], arc[1], capacity=data["capacity"])
        return graph

    def _create_subgraph(self):
        # Create subgraph from list of attackable nodes.
        nodes = []
        for node, data in self.node_data.iterrows():
            if data["attackable"] == 1:
                nodes.append(node)
        return self.graph.subgraph(nodes)

    def get_graph_with_attackable_nodes(self):
        """Return graph object with attackable nodes."""
        return self._create_subgraph()

    def load(self, xlsx_file):
        """Load network topology from Excel file."""
        self.node_data = pd.read_excel(xlsx_file, sheet_name="nodes")
        self.arc_data = pd.read_excel(xlsx_file, sheet_name="arcs")
        self.node_data.set_index(["node"], inplace=True)
        self.arc_data.set_index(["start_node", "end_node"], inplace=True)
        self.node_set = self.node_data.index.unique()
        self.arc_set = self.arc_data.index.unique()
        self.graph = self._create_graph()

    def to_excel(self, xlsx_file):
        """Write network topology to Excel file."""
        with pd.ExcelWriter(xlsx_file) as writer:  # pylint: disable=abstract-class-instantiated
            self.node_data.to_excel(writer, sheet_name="nodes", index=False)
            self.arc_data.to_excel(writer, sheet_name="arcs", index=False)

    def plot(self, filename=None, with_capacity=False, dpi=300):
        """Plot network topology."""
        pos = nx.spring_layout(self.graph)
        labels = nx.get_edge_attributes(self.graph, "capacity")
        nx.draw(self.graph, pos, with_labels=True)
        if with_capacity:
            nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=labels)
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
