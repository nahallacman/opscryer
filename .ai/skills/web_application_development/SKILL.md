---
name: web_application_development
description: Frontend Web Application Design Aesthetics, Technology Stack, Workflow, and SEO Best Practices.
---

# Web Application Development & Design Standards

This skill defines the rigorous standards and architectural choices for any frontend web applications built in this repository.

## Technology Stack
Your web applications should be built using the following technologies:
1. **Core**: Use HTML for structure and Javascript for logic.
2. **Styling (CSS)**: Use Vanilla CSS for maximum flexibility and control. Avoid using TailwindCSS unless explicitly requested; in this case, first confirm which TailwindCSS version to use.
3. **Web App**: For complex web apps, use a framework like Next.js or Vite. Only do this if explicitly requested.
4. **New Project Creation**: If you need to use a framework for a new app, use `npx` with the appropriate script:
   - Use `npx -y` to automatically install the script and its dependencies
   - You MUST run the command with `--help` flag to see all available options first
   - Initialize the app in the current directory with `./` (example: `npx -y create-vite-app@latest ./`)
   - Run in non-interactive mode so no user input is required
5. **Running Locally**: When running locally, use `npm run dev` or equivalent dev server. Only build the production bundle if explicitly requested or you are validating the code for correctness.

## Design Aesthetics
1. **Use Rich Aesthetics**: The design must WOW at first glance. Use best practices in modern web design (e.g. vibrant colors, dark modes, glassmorphism, dynamic animations) to create a stunning first impression. Failure to do this is UNACCEPTABLE.
2. **Prioritize Visual Excellence**: Implement designs that feel extremely premium:
   - Avoid generic colors (plain red, blue, green). Use curated, harmonious color palettes (e.g., HSL tailored colors, sleek dark modes).
   - Use modern typography (e.g., from Google Fonts like Inter, Roboto, or Outfit) instead of browser defaults.
   - Use smooth gradients.
   - Add subtle micro-animations for enhanced user experience.
3. **Use a Dynamic Design**: An interface that feels responsive and alive encourages interaction. Achieve this with hover effects and interactive elements. Micro-animations are highly effective for improving user engagement.
4. **Premium Designs**: Make a design that feels premium and state of the art. Avoid creating simple minimum viable products.
5. **Don't use placeholders**: If you need an image, use your `generate_image` tool to create a working demonstration.

## Implementation Workflow
Follow this systematic approach when building web applications:
1. **Plan and Understand**:
   - Fully understand the requirements.
   - Draw inspiration from modern, beautiful, and dynamic web designs.
   - Outline the features needed for the initial version.
2. **Build the Foundation**:
   - Start by creating/modifying `index.css`.
   - Implement the core design system with all tokens and utilities.
3. **Create Components**:
   - Build necessary components using your design system.
   - Ensure all components use predefined styles, not ad-hoc utilities.
   - Keep components focused and reusable.
4. **Assemble Pages**:
   - Update the main application to incorporate your design and components.
   - Ensure proper routing and navigation.
   - Implement responsive layouts.
5. **Polish and Optimize**:
   - Review the overall user experience.
   - Ensure smooth interactions and transitions.
   - Optimize performance where needed.

## SEO Best Practices
Automatically implement SEO best practices on every page:
- **Title Tags**: Include proper, descriptive title tags for each page.
- **Meta Descriptions**: Add compelling meta descriptions that accurately summarize page content.
- **Heading Structure**: Use a single `<h1>` per page with proper heading hierarchy.
- **Semantic HTML**: Use appropriate HTML5 semantic elements.
- **Unique IDs**: Ensure all interactive elements have unique, descriptive IDs for browser testing.
- **Performance**: Ensure fast page load times through optimization.

## Tactical Game-HUD Ergonomics, 6-Color Semantics & Golfed Menu Depths
Whenever designing or modifying UIs, portals (`OpsCryer`, `Dependency Mapper`), or interactive diagrams, AI agents MUST adhere to [`.ai/knowledge/workflow/ui_ux_and_visualization_standards.md`](file:///<workspace>/.ai/knowledge/workflow/ui_ux_and_visualization_standards.md):
1. **Familiar Interaction Methods & Flowing Live Diagrams**:
   - Use intuitive pan/zoom, click-to-inspect, and keyboard shortcuts (`1-6`, `/`, `Esc`).
   - Keep client-side graphics rock-solid, safe, and fast (`60fps`, GPU-safe CSS transforms, zero heavy shader/particle bloat or layout thrashing).
2. **Mandatory 6-Color Semantic Status & Anomaly Vocabulary**:
   - 🔴 **Red (`#ef4444`)**: Critical errors / failing gates.
   - 🟡 **Yellow (`#eab308`)**: Minor / non-critical issues or warnings.
   - 🟢 **Green (`#22c55e`)**: All clean / verified tests & controls.
   - 🔵 **Blue (`#3b82f6`)**: Stalled deployment / frozen rollout or stuck trajectory loop.
   - 🟠 **Orange (`#f97316`)**: Novel / unseen error signature never previously recorded in our DDR4 RAM / Knowledge Base error database.
   - 🟣 **Purple (`#a855f7`)**: Locked resource / active file or container mutex (`swarm-memory:8090/api/v1/locks`).
3. **Video-Game HUD Simplicity & Lower Technical Inspector**:
   - Top/center viewport provides instant visual scanning; clicking any node immediately populates a **Lower Technical Inspector Pane** with raw technical info, test mappings, and commands. Simplicity and speed always win over animation-heavy clutter.
4. **Golfing Down Menu Depths (`<= 1-2 Clicks`)**:
   - Never bury critical links in deep menus. Surface direct 1-click links from the UI to GitLab MRs/pipelines, source files, and remediation commands inside clear functional groupings.

> [!CAUTION]
> **CRITICAL REMINDER**: AESTHETICS AND HIGH-SPEED USABILITY ARE EQUALLY IMPORTANT. Keep visualizations fast, semantic, and effortless to navigate!

