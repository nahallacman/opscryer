# SPDX-License-Identifier: Apache-2.0
"""Offline five-turn support walkthrough and sanitized sample transcript export."""

import argparse
from html import escape
import json
from pathlib import Path

from oscal_compliance import build_oscal_hud_posture_report
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize
from ticket_chat_portal import ask_concierge_chat


_TURNS = (
    ("household_user", "Manifest Minecraft/Factorio server pods are down and the "
     "living room GPU has low FPS. How can we distinguish server trouble from client lag?"),
    ("developer", "Manifest dependencies for scaffolding a new 3-tier project and pipeline."),
    ("developer", "What is the database credentials policy for this project?"),
    ("sre", "Manifest nodebeta02 NotReady and gitlab failed runner pods: "
     "what snapshot evidence and diagnostic steps should I review?"),
    ("executive", "Manifest OSCAL compliance and cluster health summary for leadership."),
)


def run_multi_persona_chat_walkthrough(catalog=None):
    """Return five ordered question/response exchanges, using the real concierge.

    ``catalog`` accepts a graph dict or JSON path, as in the concierge. None uses
    its bundled snapshot. No polling, model calls, ticket filing or remediation
    occurs. The credentials question deliberately demonstrates the airlock;
    blocked requests receive no ticket policy evaluation. OSCAL status is an
    unassessed evidence map, not certification or a live compliance audit.
    """
    turns = []
    for number, (persona, message) in enumerate(_TURNS, 1):
        response = ask_concierge_chat(message, persona=persona, catalog=catalog)
        if persona == "executive" and response["status"] == "ok":
            response["oscal_posture"] = build_oscal_hud_posture_report()
        turns.append({"turn": number, "persona": persona,
                      "message": message, "response": response})
    blocked = sum(turn["response"]["airlock_blocked"] is True for turn in turns)
    return sanitize({
        "schema_version": "1.0-chat-walkthrough", "simulation": True,
        "turns": turns,
        "summary": {"total": len(turns), "allowed": len(turns) - blocked,
                    "blocked": blocked},
        "notice": "Simulated conversation using snapshot evidence; observations do not "
                  "establish a root cause. No tickets filed or system changes made. "
                  "OSCAL controls are not assessed; this is not compliance certification.",
    })


def render_transcript(result):
    """Render the same sanitized evidence used by the JSON transcript."""
    result = sanitize(result)
    lines = ["OpsCryer multi-persona chat walkthrough", result["notice"]]
    for turn in result["turns"]:
        response = turn["response"]
        lines.extend(["", f'Turn {turn["turn"]} [{turn["persona"]}]',
                      "User: " + turn["message"],
                      f'Assistant [{response["status_badge"]}]: '
                      + response["plain_english_answer"]])
        # Preserve policy cards, diagnostics and citations in the text export too.
        evidence = {key: value for key, value in response.items()
                    if key not in {"plain_english_answer", "quick_reply_chips"}}
        lines.append("Evidence: " + json.dumps(evidence, indent=2, allow_nan=False))
    return "\n".join(lines)


def render_walkthrough_markdown(result=None) -> str:
    """Render a sanitized presentation sheet without modifying supplied results."""
    result = sanitize(run_multi_persona_chat_walkthrough() if result is None else result)

    def text(value):
        # Keep supplied text from creating table cells, links or HTML elements.
        value = escape(str(value), quote=False).replace("\\", "\\\\")
        for character in "`*_[]|":
            value = value.replace(character, "\\" + character)
        return "<br>".join(value.splitlines())

    lines = ["# OpsCryer multi-persona chat walkthrough", "", text(result["notice"]), "",
             "| Turn | Persona | Status Badge | Airlock Blocked | Policy ID |",
             "| --- | --- | --- | --- | --- |"]
    for turn in result["turns"]:
        response = turn["response"]
        policy = (response.get("ticket_card") or {}).get("policy_id") or "N/A"
        cells = (turn["turn"], turn["persona"], response["status_badge"],
                 "Yes" if response["airlock_blocked"] else "No", policy)
        lines.append("| " + " | ".join(text(cell) for cell in cells) + " |")

    for turn in result["turns"]:
        response = turn["response"]
        lines.extend(["", f'## Turn {text(turn["turn"])}: {text(turn["persona"])}', "",
                      "**User:** " + text(turn["message"]), "",
                      "**Assistant:** " + text(response["plain_english_answer"]), "",
                      "**Suggested next steps:**", ""])
        steps = response.get("suggested_next_steps", [])
        lines.extend("- " + text(step) for step in steps)
        if not steps:
            lines.append("None; request blocked by the airlock." if response["airlock_blocked"]
                         else "None suggested.")
        evidence = {key: value for key, value in response.items()
                    if key not in {"plain_english_answer", "quick_reply_chips"}}
        encoded = json.dumps(evidence, indent=2, allow_nan=False)
        # A longer fence prevents supplied evidence from closing the code block.
        fence = "~" * (encoded.count("~") + 3)
        lines.extend(["", "<details>", "<summary>Policy, diagnostics and cited evidence</summary>",
                      "", fence + "json", encoded, fence, "", "</details>"])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    formats = parser.add_mutually_exclusive_group()
    formats.add_argument("--json", action="store_true", help="Export the transcript as JSON")
    formats.add_argument("--markdown", action="store_true", help="Export a Markdown presentation sheet")
    args = parser.parse_args(argv)
    try:
        result = run_multi_persona_chat_walkthrough(catalog=args.catalog)
        output = (json.dumps(result, indent=2, allow_nan=False) if args.json
                  else render_walkthrough_markdown(result) if args.markdown
                  else render_transcript(result))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        parser.error("Unable to build walkthrough from a valid cluster catalog")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
