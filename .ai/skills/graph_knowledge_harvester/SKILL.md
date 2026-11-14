---
name: graph_knowledge_harvester
description: Harvest operational observations from cluster services into Knowledge Graph nodes and dry-run validate new System One Jev decision tree playbooks.
---

# Graph Knowledge Harvester & Jev Auto-Proposer Skill

Use this skill when gathering operational knowledge from cluster services (`Harbor`, `GitLab`, `OpenZFS`, `Authentik`, `OpenBao`) to enrich the Knowledge Graph and propose verified support ticket playbooks to `Jev`.

## CLI Commands
```powershell
# 1. Dry-run harvest and validate all proposals through the 4-Gate Jev Sandbox
python scripts/devops/graph_knowledge_harvester.py propose-all

# 2. Export Knowledge Graph entity and relationship enrichment patch
python scripts/devops/graph_knowledge_harvester.py graph-patch

# 3. Run the 4-Epoch Progressive Knowledge Graph Training Curriculum across all 8 settled production systems
python scripts/devops/graph_knowledge_harvester.py train-settled
python opscryer_abstraction.py --train-graph-over-time
```
