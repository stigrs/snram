# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Provides SNRAM test cases."""

import os
import unittest
import numpy as np
from snram.topology import NetworkTopology
from snram.max_flow_interdict import MaxFlowInterdiction
from snram.sp_interdict import SPInterdiction
from snram.min_cost_flow_interdict import MinCostFlowInterdiction


class TestSNRAM(unittest.TestCase):
    def test_case1(self):
        # Max-flow interdiction from PyomoGallery.
        ans = [80.0, 10.0, 0.0]

        fname = os.path.join("tests", "test_case1.xlsx")
        topology = NetworkTopology(fname)

        solver = "glpk"
        attack = 0

        model = MaxFlowInterdiction(topology, attack, solver)
        primal, idual = model.solve()

        self.assertTrue(np.allclose(primal.OBJ(), ans[0], atol=0.001))
        self.assertTrue(np.allclose(idual.OBJ(), ans[0], atol=0.001))

        model.set_attacks(1)
        primal, idual = model.solve()

        self.assertTrue(np.allclose(primal.OBJ(), ans[1], atol=0.001))
        self.assertTrue(np.allclose(idual.OBJ(), ans[1], atol=0.001))

        model.set_attacks(2)
        primal, idual = model.solve()

        self.assertTrue(np.allclose(primal.OBJ(), ans[2], atol=0.001))
        self.assertTrue(np.allclose(idual.OBJ(), ans[2], atol=0.001))

    def test_case2(self):
        # Shortest-path interdiction from PyomoGallery.
        ans = [5.0, 17.0, 100.0]

        fname = os.path.join("tests", "test_case2.xlsx")
        topology = NetworkTopology(fname)

        solver = "glpk"
        attack = 0

        model = SPInterdiction(topology, attack, solver)
        primal, idual = model.solve()

        self.assertTrue(np.allclose(primal.OBJ(), ans[0], atol=0.001))
        self.assertTrue(np.allclose(idual.OBJ(), ans[0], atol=0.001))

        model.set_attacks(1)
        primal, idual = model.solve()

        self.assertTrue(np.allclose(primal.OBJ(), ans[1], atol=0.001))
        self.assertTrue(np.allclose(idual.OBJ(), ans[1], atol=0.001))

        model.set_attacks(2)
        primal, idual = model.solve()

        self.assertTrue(np.allclose(primal.OBJ(), ans[2], atol=0.001))
        self.assertTrue(np.allclose(idual.OBJ(), ans[2], atol=0.001))

    def test_case3(self):
        # Min-cost-flow interdiction from PyomoGallery.
        ans = [700.0, 7300.0, 21000.0]

        fname = os.path.join("tests", "test_case3.xlsx")
        topology = NetworkTopology(fname)

        solver = "glpk"
        attack = 0

        model = MinCostFlowInterdiction(topology, attack, solver)
        primal, idual = model.solve()

        self.assertTrue(np.allclose(primal.OBJ(), ans[0], atol=0.001))
        self.assertTrue(np.allclose(idual.OBJ(), ans[0], atol=0.001))

        model.set_attacks(1)
        primal, idual = model.solve()

        self.assertTrue(np.allclose(primal.OBJ(), ans[1], atol=0.001))
        self.assertTrue(np.allclose(idual.OBJ(), ans[1], atol=0.001))

        model.set_attacks(2)
        primal, idual = model.solve()

        self.assertTrue(np.allclose(primal.OBJ(), ans[2], atol=0.001))
        self.assertTrue(np.allclose(idual.OBJ(), ans[2], atol=0.001))

if __name__ == "__main__":
    unittest.main()
