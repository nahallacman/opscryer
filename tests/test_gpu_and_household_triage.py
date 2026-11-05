# SPDX-License-Identifier: Apache-2.0
"""GPU ownership invariants and household diagnostic routing contracts."""

import json
import unittest

from gpu_and_household_triage import (
    VERIFIED_FOUR_GPU_INVENTORY,
    allocate_gpu_workload_profile,
    allocate_verified_four_gpu_workload_profile,
    triage_household_game_ticket,
)


class GPUWorkloadTests(unittest.TestCase):
    def test_all_modes_assign_each_device_once_without_pooling(self):
        expectations = {
            "ai_swarm": (["ai_swarm"] * 3, {"ai_swarm": 34, "gaming_lan": 0}),
            "gaming_lan": (["gaming_lan"] * 3, {"ai_swarm": 0, "gaming_lan": 34}),
            "hybrid_balanced": (["ai_swarm", "gaming_lan", "gaming_lan"],
                                {"ai_swarm": 16, "gaming_lan": 18}),
        }
        for mode, (roles, capacity) in expectations.items():
            with self.subTest(mode=mode):
                plan = allocate_gpu_workload_profile(mode)
                self.assertEqual(plan["mode"], mode)
                self.assertEqual([(g["model"], g["vram_gb"]) for g in plan["gpus"]],
                                 [("RTX 5080", 16), ("RTX 3080", 10), ("RTX 3070", 8)])
                self.assertEqual(len({g["id"] for g in plan["gpus"]}), 3)
                self.assertTrue(all(g["exclusive"] for g in plan["gpus"]))
                self.assertEqual([g["workload"] for g in plan["gpus"]], roles)
                self.assertEqual(plan["workload_capacity_gb"], capacity)
                self.assertEqual(sum(capacity.values()), plan["total_vram_gb"])
                self.assertFalse(plan["vram_pooled"])
                self.assertTrue(plan["simulation"])
                self.assertTrue(plan["transition_steps"])
                json.dumps(plan, allow_nan=False)

    def test_default_and_returned_plans_are_independent(self):
        plan = allocate_gpu_workload_profile()
        self.assertEqual(plan, allocate_gpu_workload_profile("hybrid_balanced"))
        plan["gpus"][0]["vram_gb"] = 0
        plan["transition_steps"].clear()
        fresh = allocate_gpu_workload_profile()
        self.assertEqual(fresh["gpus"][0]["vram_gb"], 16)
        self.assertTrue(fresh["transition_steps"])

    def test_invalid_modes(self):
        for mode in (None, True, 1, [], {}, "", "AI_SWARM", "unknown"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                allocate_gpu_workload_profile(mode)

    def test_verified_four_gpu_inventory_has_40gb_vram_and_exclusive_assignment(self):
        self.assertEqual(len(VERIFIED_FOUR_GPU_INVENTORY), 4)
        for mode, workloads, totals in (
            ("hybrid_balanced", ["ai_swarm", "gaming_lan", "ai_swarm", "gaming_lan"], (21, 19)),
            ("ai_swarm", ["ai_swarm"] * 4, (40, 0)),
            ("gaming_lan", ["gaming_lan"] * 4, (0, 40)),
        ):
            with self.subTest(mode=mode):
                result = allocate_verified_four_gpu_workload_profile(mode)
                self.assertEqual(result["total_vram_gb"], 40)
                self.assertFalse(result["vram_pooled"])
                self.assertEqual([g["vram_gb"] for g in result["gpus"]], [10, 8, 11, 11])
                self.assertEqual([g["workload"] for g in result["gpus"]], workloads)
                self.assertEqual(
                    result["workload_capacity_gb"],
                    {"ai_swarm": totals[0], "gaming_lan": totals[1]},
                )


class HouseholdTriageTests(unittest.TestCase):
    def test_auto_routes_symptoms_to_each_layer(self):
        cases = {
            1: ["the minecraft server is down", "Pod CrashLoopBackOff", "server tick lag",
                "game server unavailable", "pods are unavailable"],
            2: ["minecraft.cluster.example.org fails", "IP works but hostname fails", "LAN packet loss",
                "NXDOMAIN", "connection timed out", "hostname cannot resolve",
                "name won't resolve"],
            3: ["APU-200 APU thermal throttling", "RTX 3070 VRAM full", "LOW FPS and stuttering",
                "FPS dropping during play"],
        }
        for layer, questions in cases.items():
            for question in questions:
                with self.subTest(question=question):
                    plan = triage_household_game_ticket(question)
                    self.assertEqual(plan["primary_layer"], layer)
                    self.assertEqual(plan["matched_layers"], [layer])
                    self.assertEqual(plan["status"], "diagnostic_plan")
                    self.assertEqual(plan["diagnostic_order"][0], layer)
                    self.assertEqual(set(plan["diagnostic_order"]), {1, 2, 3})
                    self.assertEqual([d["layer"] for d in plan["diagnostics"]],
                                     plan["diagnostic_order"])
                    self.assertTrue(all(d["checks"] for d in plan["diagnostics"]))
                    self.assertEqual(plan["clarifying_questions"], [])
                    json.dumps(plan, allow_nan=False)

    def test_unknown_and_cross_layer_tickets_request_clarification(self):
        for question, matches in (("help with minecraft", []),
                                  ("server down and DNS broken", [1, 2]),
                                  ("DNS and VRAM problems", [2, 3])):
            with self.subTest(question=question):
                plan = triage_household_game_ticket(question)
                self.assertIsNone(plan["primary_layer"])
                self.assertEqual(plan["status"], "needs_clarification")
                self.assertEqual(plan["matched_layers"], matches)
                self.assertTrue(plan["clarifying_questions"])
                self.assertEqual(set(plan["diagnostic_order"]), {1, 2, 3})

    def test_explicit_scenario_overrides_keywords(self):
        for layer, scenario in enumerate(
                ("game_server_pods", "internal_lan_dns", "client_gpu"), 1):
            plan = triage_household_game_ticket("DNS and GPU trouble", scenario)
            self.assertEqual(plan["primary_layer"], layer)
            self.assertEqual(plan["diagnostic_order"][0], layer)
            self.assertEqual(plan["reason"], "explicit_scenario")

    def test_all_layers_remain_available_for_cross_layer_reports(self):
        plan = triage_household_game_ticket(
            "server unavailable, DNS fails and APU-200 overheats")
        self.assertEqual(plan["matched_layers"], [1, 2, 3])
        self.assertEqual(plan["diagnostic_order"], [1, 2, 3])
        self.assertEqual(plan["reason"], "multiple_layer_symptoms")
        self.assertIsNone(plan["primary_layer"])
        self.assertEqual(plan["status"], "needs_clarification")
        self.assertTrue(plan["clarifying_questions"])

    def test_partial_keywords_do_not_route_unrelated_tickets(self):
        plan = triage_household_game_ticket("pendingly named pingpong artifactsmith")
        self.assertEqual(plan["matched_layers"], [])
        self.assertEqual(plan["reason"], "insufficient_symptoms")

    def test_ticket_text_is_not_exposed_or_executed(self):
        # Build synthetic sensitive-looking input without storing identifiers.
        question = "DNS issue " + ":".join(["AB"] * 6) + " gh" + "p_" + "example"
        output = json.dumps(triage_household_game_ticket(question))
        self.assertNotIn(question, output)
        self.assertNotIn(":".join(["AB"] * 6), output)
        self.assertNotIn("gh" + "p_" + "example", output)
        self.assertTrue(triage_household_game_ticket(question)["simulation"])

    def test_returned_diagnostics_are_independent(self):
        plan = triage_household_game_ticket("DNS broken")
        plan["diagnostics"][0]["checks"].clear()
        plan["matched_layers"].clear()
        fresh = triage_household_game_ticket("DNS broken")
        self.assertTrue(fresh["diagnostics"][0]["checks"])
        self.assertEqual(fresh["matched_layers"], [2])

    def test_invalid_inputs_do_not_echo_sensitive_values(self):
        for question in (None, True, 3, [], {}, "", " \n\t"):
            with self.subTest(question=question), self.assertRaises(ValueError):
                triage_household_game_ticket(question)
        for scenario in (None, True, 1, [], {}, "", "AUTO", "private-input"):
            with self.subTest(scenario=scenario):
                with self.assertRaises(ValueError) as caught:
                    triage_household_game_ticket("help", scenario)
                self.assertNotIn("private-input", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
