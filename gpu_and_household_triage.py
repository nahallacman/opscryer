# SPDX-License-Identifier: Apache-2.0
"""Offline GPU assignment plans and deterministic household ticket triage.

These functions model plans, not hardware discovery, live health measurements,
or an executable workload switch. Returned containers are fresh and JSON-safe.
"""

import re


def allocate_gpu_workload_profile(mode="hybrid_balanced"):
    """Assign each GPU exclusively to AI or gaming, with no VRAM pooling.

    ``ai_swarm`` dedicates all three devices to independent AI workers;
    ``gaming_lan`` dedicates all three to LAN gaming clients. The default keeps
    the 16 GB device for AI and the 10/8 GB devices for gaming. Capacity is a
    nominal per-device budget, not free VRAM or a model-fit guarantee. Applying
    a plan requires draining existing work before changing device ownership.
    Unsupported modes (including nonstrings) raise ValueError.
    """
    modes = ("ai_swarm", "gaming_lan", "hybrid_balanced")
    if not isinstance(mode, str) or mode not in modes:
        raise ValueError("mode must be ai_swarm, gaming_lan, or hybrid_balanced")
    gpus = []
    for index, (model, capacity) in enumerate(
            (("RTX 5080", 16), ("RTX 3080", 10), ("RTX 3070", 8))):
        workload = "ai_swarm" if (
            mode == "ai_swarm" or mode == "hybrid_balanced" and index == 0
        ) else "gaming_lan"
        gpus.append({"id": f"gpu-{index}", "model": model,
                     "vram_gb": capacity, "workload": workload,
                     "exclusive": True})
    return {
        "schema_version": 1, "mode": mode, "simulation": True,
        "gpus": gpus, "total_vram_gb": 34, "vram_pooled": False,
        "workload_capacity_gb": {
            workload: sum(gpu["vram_gb"] for gpu in gpus
                          if gpu["workload"] == workload)
            for workload in ("ai_swarm", "gaming_lan")
        },
        "transition_steps": [
            "Drain and stop current workloads on each reassigned GPU.",
            "Confirm the device is idle and release its existing reservation.",
            "Reserve each GPU exclusively for its planned workload.",
            "Check free VRAM and workload health before admitting new work.",
        ],
    }


def build_three_gpu_workload_plan(mode="hybrid_balanced") -> dict:
    """Build the nominal three-device plan using the shared ownership rules."""
    return allocate_gpu_workload_profile(mode)


VERIFIED_FOUR_GPU_INVENTORY = (
    ("gpu-rtx-3080", "NVIDIA GeForce RTX 3080", 10, "workstation-desktop"),
    ("gpu-rtx-3070-ti", "NVIDIA GeForce RTX 3070 Ti", 8, "workstation-secondary"),
    ("gpu-gtx-1080-ti-0", "NVIDIA GeForce GTX 1080 Ti", 11, "nodegamma03"),
    ("gpu-gtx-1080-ti-1", "NVIDIA GeForce GTX 1080 Ti", 11, "cluster-gpu-worker-2"),
)


def allocate_verified_four_gpu_workload_profile(mode="hybrid_balanced") -> dict:
    """Assign the verified 4-GPU inventory (1x RTX 3080 10GB, 1x RTX 3070 Ti 8GB, 2x GTX 1080 Ti 11GB = 40 GB VRAM)."""
    modes = ("ai_swarm", "gaming_lan", "hybrid_balanced")
    if not isinstance(mode, str) or mode not in modes:
        raise ValueError("mode must be ai_swarm, gaming_lan, or hybrid_balanced")
    gpus = []
    for index, (gpu_id, model, capacity, host_node) in enumerate(VERIFIED_FOUR_GPU_INVENTORY):
        workload = "ai_swarm" if (
            mode == "ai_swarm" or (mode == "hybrid_balanced" and index in (0, 2))
        ) else "gaming_lan"
        gpus.append({
            "id": gpu_id,
            "model": model,
            "vram_gb": capacity,
            "host_node": host_node,
            "workload": workload,
            "exclusive": True,
        })
    return {
        "schema_version": 1,
        "mode": mode,
        "simulation": True,
        "gpus": gpus,
        "total_vram_gb": 40,
        "vram_pooled": False,
        "workload_capacity_gb": {
            workload: sum(gpu["vram_gb"] for gpu in gpus if gpu["workload"] == workload)
            for workload in ("ai_swarm", "gaming_lan")
        },
        "transition_steps": [
            "Drain and stop current workloads on each reassigned GPU.",
            "Confirm the device is idle and release its existing reservation.",
            "Reserve each GPU exclusively for its planned workload.",
            "Check free VRAM and workload health before admitting new work.",
        ],
    }


# Patterns describe symptoms, rather than merely naming a game or GPU.
_LAYERS = (
    (1, "game_server_pods", "Game Server Pods", (
        r"\b(?:server|pod)s?\s+(?:is\s+|are\s+)?(?:down|offline|unavailable|crashing|crashed)\b",
        r"\b(?:crashloopbackoff|crashloop|pending|oomkilled)\b",
        r"\b(?:server|pod)\s+(?:logs?|restart\w*|readiness|tick\s+lag)\b",
    ), (
        "Check game server pod readiness, restarts, scheduling events and recent logs.",
        "Check Service endpoints, game port/protocol and persistent world storage.",
        "Compare server tick time and resource pressure across affected players.",
    )),
    (2, "internal_lan_dns", "Internal LAN / .cluster.example.org Split-Horizon DNS", (
        r"\.cluster\.example\.org\b", r"\b(?:dns|nxdomain|split[ -]horizon)\b",
        r"\b(?:hostname|name)\s+(?:fails?|doesn.t\s+resolve|cannot\s+resolve|"
        r"won.t\s+resolve|not\s+resolv\w*)\b",
        r"\b(?:packet\s+loss|lan|vlan|dhcp|wi[ -]?fi|latency|ping)\b",
        r"\b(?:ip\s+works|connection\s+(?:timed?\s*out|refused))\b",
    ), (
        "Compare access by internal LAN address with access by .cluster.example.org hostname.",
        "Query the client-configured internal DNS resolver for the .cluster.example.org record; "
        "verify its RFC 1918 answer and split-horizon view.",
        "Check DHCP DNS settings, stale caches, VLAN reachability, packet loss and game ports.",
    )),
    (3, "client_gpu", "Client GPU / APU-200 APU Thermals & VRAM", (
        r"\b(?:gpu|vram|apu|bc[ -]?250)\b",
        r"\b(?:low\s+fps|fps\s+drop(?:s|ping)?|stutter\w*|artifacts?|thermal\w*|overheat\w*)\b",
        r"\b(?:frame\s*(?:time|rate)|temperature|throttl\w*)\b",
    ), (
        "Compare another client on the same server to isolate local frame-time problems.",
        "Inspect client GPU or APU-200 APU temperature, clock throttling, cooling and driver logs.",
        "Check dedicated VRAM use or APU-200 shared-memory pressure; compare texture settings "
        "and competing AI workloads with the device budget.",
    )),
)


def triage_household_game_ticket(question, scenario="auto"):
    """Return a three-layer diagnostic plan without I/O or echoing ticket text.

    ``scenario`` accepts auto, game_server_pods, internal_lan_dns or client_gpu.
    An explicit scenario selects a starting layer regardless of keyword matches.
    Auto selects a layer only when exactly one layer has symptom matches;
    unknown and multi-layer tickets request clarification. All three checklists
    remain available, with matched layers first in numerical order. Matches are
    routing hints, not confirmed diagnoses; negation is not interpreted.
    Empty/nonstring questions and invalid scenarios raise ValueError without
    including potentially sensitive input in the error or returned plan.
    """
    if not isinstance(question, str) or not question.strip():
        raise ValueError("question must be a nonempty string")
    scenarios = ("auto",) + tuple(layer[1] for layer in _LAYERS)
    if not isinstance(scenario, str) or scenario not in scenarios:
        raise ValueError("scenario must be auto, game_server_pods, internal_lan_dns, or client_gpu")
    matched = [number for number, _, _, patterns, _ in _LAYERS
               if any(re.search(pattern, question, re.IGNORECASE) for pattern in patterns)]
    if scenario != "auto":
        primary = next(layer[0] for layer in _LAYERS if layer[1] == scenario)
        reason = "explicit_scenario"
    elif len(matched) == 1:
        primary, reason = matched[0], "single_layer_symptoms"
    else:
        primary = None
        reason = "multiple_layer_symptoms" if matched else "insufficient_symptoms"
    order = ([primary] if primary else matched[:])
    order += [number for number in (1, 2, 3) if number not in order]
    diagnostics = [
        {"layer": number, "scenario": name, "title": title, "checks": list(checks)}
        for number, name, title, _, checks in _LAYERS
    ]
    return {
        "schema_version": 1, "scenario": scenario, "simulation": True,
        "status": "diagnostic_plan" if primary else "needs_clarification",
        "primary_layer": primary, "matched_layers": matched, "reason": reason,
        "diagnostic_order": order,
        "diagnostics": [diagnostics[number - 1] for number in order],
        "clarifying_questions": [] if primary else [
            "Are all players affected, or only one client?",
            "Does the internal LAN address work when the .cluster.example.org name fails?",
            "Is the server unavailable, or is the client showing low FPS or thermal throttling?",
        ],
    }
