#!/usr/bin/env python
#
# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

"""Program for running SNRAM."""

import argparse
from snram.driver import driver


def _parse_args():
    # Parse command line arguments.
    parser = argparse.ArgumentParser(
        description="Suite of Network Risk Assessment Methods")
    parser.add_argument("-f", "--file",
                        action="store",
                        dest="xlsx_file",
                        required=True,
                        help="name of Excel file with topology (xlsx)")
    parser.add_argument("-s", "--save",
                        action="store",
                        dest="save_xlsx",
                        default=None,
                        required=False,
                        help="name of Excel file for saving topology (xlsx)")
    parser.add_argument("-p", "--png",
                        action="store",
                        dest="png_file",
                        default=None,
                        required=False,
                        help="name of PNG file for saving topology")
    parser.add_argument("-r", "--run",
                        action="store",
                        dest="run_type",
                        choices=["critical_asset", "prepare", "mitigate",
                                 "threat", "stackelberg", "interdict"],
                        default="critical_asset",
                        required=False,
                        help="type of simulation run")
    parser.add_argument("-b", "--budget",
                        action="store",
                        dest="budget",
                        default=1,
                        type=int,
                        required=False,
                        help="budget size")
    parser.add_argument("-k", "--attacks",
                        action="store",
                        dest="attacks",
                        default=0,
                        type=int,
                        required=False,
                        help="number of attacks")
    parser.add_argument("-i", "--interdict",
                        action="store",
                        dest="interdict",
                        choices=["max-flow", "min-cost-flow", "shortest-path"],
                        default="min-cost-flow",
                        required=False,
                        help="network interdiction problem")
    parser.add_argument("-o", "--solver",
                        action="store",
                        dest="solver",
                        choices=["cplex", "glpk", "ipopt"],
                        default="cplex",
                        required=False,
                        help="solver")
    parser.add_argument("-n", "--max_iter",
                        action="store",
                        dest="max_iter",
                        default=10,
                        type=int,
                        required=False,
                        help="maximum number of iterations")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        required=False,
                        help="verbose output")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()  # pylint: disable=invalid-name
    driver(args.xlsx_file,
           png_file=args.png_file,
           save_xlsx=args.save_xlsx,
           run_type=args.run_type,
           budget=args.budget,
           interdict=args.interdict,
           attacks=args.attacks,
           solver=args.solver,
           max_iter=args.max_iter,
           tee=args.verbose)
