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
        self.link_data = None
        self.node_set = None
        self.link_set = None
        self.graph = None

        # Load network topology from Excel file:
        self.load(xlsx_file)

    def _create_graph(self):
        # Create graph from list of attackable nodes.
        graph = nx.Graph()
        for link, data in self.link_data.iterrows():
            graph.add_edge(link[0], link[1], capacity=data["capacity"])
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
        self.link_data = pd.read_excel(xlsx_file, sheet_name="links")
        self.node_data.set_index(["node"], inplace=True)
        self.link_data.set_index(["start_node", "end_node"], inplace=True)
        self.node_set = self.node_data.index.unique()
        self.link_set = self.link_data.index.unique()
        self.graph = self._create_graph()

    def to_excel(self, xlsx_file):
        """Write network topology to Excel file."""
        with pd.ExcelWriter(xlsx_file) as writer:  # pylint: disable=abstract-class-instantiated
            self.node_data.to_excel(writer, sheet_name="nodes", index=False)
            self.link_data.to_excel(writer, sheet_name="links", index=False)

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

    def link_betweenness_centrality(self):
        """Compute normalised link betweenness centrality."""
        graph = self.get_graph_with_attackable_nodes()
        betweenness = list(nx.edge_betweenness_centrality(graph).values())
        betweenness /= np.max(betweenness)
        return betweenness
