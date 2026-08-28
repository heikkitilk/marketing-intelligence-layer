---
description: Build or update your Marketing Intelligence Layer from raw notes and files. Use /build for local files, /build drive for Google Drive, /build setup to change your settings.
---

# /build — Marketing Intelligence Layer Builder

Three modes:
- **`/build`** — read notes from the local `raw/` folder
- **`/build drive`** — read notes from a Google Drive folder
- **`/build setup`** — change your name, role, or topics (re-runs the setup questions)
- **`/build sessions`** — create a private session-analysis preflight or review extracted candidates

---

## Sessions mode (`/build sessions`)

Keep the existing build modes unchanged. For `/build sessions`, require the
private U1 manifest, U2 packet manifest, U2 packet directory, and an ignored
private output root, then run:

```sh
marketing-intelligence sessions --manifest <u1-manifest> --packet-manifest <u2-packet-manifest> --packet-root <u2-packets> --output-root <ignored-u3-root>
```

This command only accounts for dependence groups, writes resumable private
work items, and enforces the resource envelope before dispatch. It never sends
packet content to a provider.

The August 17-24 proof of concept uses a human-review continuation after the
bounded value probe. Prepare the private review workbench with:

```sh
marketing-intelligence review prepare --value-probe-receipt <private-value-probe-receipt> --output-root <ignored-review-root>
```

Use a fresh ignored review root for every run; the command refuses to overwrite
an existing queue. Show the generated `review.html` page. Every candidate starts pending. The
reviewer must accept, edit, or reject every candidate, then export
`review-decisions.json`. Do not treat machine qualification or the U7 scores as
approval to publish.

After the complete decision file exists, publish only accepted and edited
candidates with:

```sh
chmod 600 <review-decisions.json>
marketing-intelligence review publish --queue <ignored-review-root>/review-queue.json --decisions <review-decisions.json> --output-root <ignored-publication-root>
```

An incomplete decision set, a queue hash mismatch, or an invalid edit blocks
publication. Full-corpus unattended extraction remains deferred; this review
path does not rewrite the historical U7 reduced-scope result.

---

## Step 0: Get ready

### Is this the first time?

**Local mode:** Look for `index.html` in the project root.
**Drive mode:** Look for `index.html` in the Drive root folder.

- If it exists, this is an **update** — new learnings will be added to the existing intelligence layer.
- If it doesn't exist, this is a **first build** — a fresh intelligence layer will be created.

### First-time setup

If `config.json` doesn't exist yet, walk the user through setup before doing anything else:

> "Before we start, I need a few things:"

**1. Name and role:**

> "1. **Your name** — this goes at the top of your intelligence layer
> 2. **Your role** — e.g. 'VP Marketing', 'Head of Growth', 'CMO'"

**2. Custom topics:**

> "Your intelligence layer comes with 8 default topics: Demand Generation, Paid Advertising, SEO, Content Marketing, Attribution & Measurement, Product Marketing, Activation & Onboarding, and Leadership & Strategy.
>
> Want to add any of your own? For example, 'AI in Marketing', 'Brand', 'Partnerships', 'Community'. Just list them — you can always add more later by running `/build setup`."

If the user provides custom topics, ask for a one-line description of each so the routing logic knows what belongs there.

Save everything to `config.json`:
```json
{
  "user_name": "Jane Smith",
  "user_role": "VP Marketing",
  "custom_topics": [
    {"id": "ai-marketing", "name": "AI in Marketing", "description": "Using AI tools and agents in marketing workflows, AI strategy, prompt engineering for marketers"},
    {"id": "partnerships", "name": "Partnerships", "description": "Partner programs, co-marketing, channel partnerships, affiliate strategy"}
  ]
}
```

If they don't want custom topics, leave `custom_topics` as an empty array.

For **Drive mode**, also ask:

> "What's the name of your Google Drive folder? This is the folder where your intelligence layer and notes live. (e.g. 'My Intelligence Layer', 'Marketing Notes')"

Search Drive for a folder matching that name. If multiple matches, show them and ask which one. Then check that this folder has a `raw` subfolder inside it — that's where the user drops notes to be processed. If the `raw` subfolder doesn't exist, create it and tell the user:

> "I've created a `raw` folder inside your Drive folder. Drop any notes, docs, or meeting transcripts in there, then run `/build drive` again."

Save the folder name, root folder ID, and raw folder ID to `config.json` so they never need to answer this again.

If Drive is not connected, tell the user: "Google Drive isn't connected yet. You'll need to add it as a connector in your Claude Code settings first, then run `/build drive` again."

### Setup mode (`/build setup`)

If the user runs `/build setup`, read the existing `config.json` and show them their current settings:

> "Here are your current settings:
> - **Name**: Jane Smith
> - **Role**: VP Marketing
> - **Custom topics**: AI in Marketing, Partnerships
>
> What would you like to change? You can update your name, role, add new topics, or remove existing ones."

Update `config.json` with their changes and stop. If they added new topics, let them know existing learnings won't be re-routed — only new learnings from future `/build` runs will use the new topics.

### Find new files

Both modes work the same way — `raw/` is the inbox, `archive/` is where copies go after processing:

**Local mode:** List all files in `raw/`. Check `raw/.processed.md` for files already processed in previous runs — skip those. If `archive/` doesn't exist, create it.

**Drive mode:** List all files in the `raw` subfolder of the Drive root folder. Check `.processed.md` (in the Drive root folder) for file IDs already processed — skip those. If `archive/` doesn't exist, create it.

Tell the user what you found:

> "Found 3 new files to process: `q4-notes.md`, `hubspot-learnings.txt`, `meeting-recap.md`"

If nothing new, say "No new files to process — add more notes and run `/build` again." and stop.

---

## Step 1: Read and extract

Read each new file. Source files can be anything — markdown, plain text, Google Docs, meeting transcripts, bullet lists, voice memo transcripts, structured notes, or free-form writing. The skill handles all of them.

Extract every distinct **learning** — a piece of knowledge, insight, framework, metric, formula, decision, outcome, or experience that a marketer would want to remember. Be thorough: pull everything worth keeping, not just the obvious headlines.

**Confidentiality filter:** This intelligence layer captures transferable knowledge, not proprietary company data. Skip or generalize anything that is company-confidential:
- **Skip entirely:** exact revenue figures, internal financial targets, unreleased product names, org charts, individual employee names, board or investor information, customer lists, pricing that isn't public
- **Generalize:** instead of "we hit $14.2M ARR in Q3", write "revenue grew significantly in the second half of the year." Instead of naming a specific internal tool, describe its function. Instead of "Sarah on the paid team discovered...", write "the paid team discovered..."
- **Keep:** frameworks, strategies, what worked vs. didn't, how you thought about a problem, public metrics, role-level descriptions (e.g. "hired a VP of Demand Gen"), general team sizes ("grew the team from 3 to 12")

For each learning, capture:
- **Title**: a short, descriptive name (5-10 words)
- **Content**: the full learning written in plain, complete language (2-4 sentences). This intelligence layer is designed to be used by AI assistants and people who need to understand each learning cold — without having seen the source material. Write every summary as if the reader has zero context. No shorthand, no abbreviations, no compressed bullet-style notation. Use full sentences that explain the what, why, and how. For example, don't write "SEM 85% · Affiliate 10% · Emerging 5%". Instead write "The demand capture budget should be split roughly 85% to search engine marketing, 10% to affiliate partners, and 5% to emerging channels like ChatGPT, Reddit, and LinkedIn — a deliberate diversification hedge against declining search demand and rising costs."
- **Type**: what kind of content this is:
  - `metric` — a number, KPI, or measurement result
  - `finding` — an insight, observation, or conclusion
  - `formula` — a framework, mental model, or repeatable process
  - `win` — something that worked well
  - `loss` — something that didn't work, with the lesson
  - `callout` — a counter-intuitive or high-importance insight
  - `channel` — a strategy or learning specific to a marketing channel
- **Source**: the filename it came from

---

## Step 2: Route each learning

For each learning, decide where it belongs. Apply the **highest tier that fits**:

### Tier 1 — Topic page

Route to the most specific marketing topic:

| Topic | What belongs here |
|---|---|
| Demand generation | Pipeline creation, lead gen, funnel mechanics, growth loops, MQL/SQL, pipeline velocity |
| Paid advertising | Channel strategy, ROAS, budget allocation, creative testing, paid social, SEM, display |
| SEO | Organic growth, technical SEO, content-led acquisition, keyword strategy, AEO/AI search |
| Content marketing | Content strategy, distribution, editorial operations, content measurement, thought leadership |
| Attribution & measurement | Multi-touch models, incrementality, marketing analytics, data infrastructure, reporting |
| Product marketing | Positioning, messaging, launches, competitive intel, market research, pricing |
| Activation & onboarding | User activation, onboarding flows, aha moments, time-to-value, PLG, trials |
| Leadership & strategy | Team building, org design, exec communication, strategic planning, budgeting, hiring |

**Custom topics:** If `config.json` contains a `custom_topics` array, include those as additional routing targets. Each custom topic has an `id`, `name`, and `description` field that tells the router what belongs there.

**Routing judgment calls:**
- "How we structured the paid team" → Leadership, not Paid — it's about org design, not ad strategy.
- "ROAS formula we used" → Paid — it's a paid-specific framework.
- "How I measured content ROI" → Attribution — it's about measurement, even though it mentions content.
- When genuinely ambiguous, route to where someone would *look for it*.

### Tier 2 — Experience page

Learnings about what happened at a specific company — accomplishments, company-specific decisions, teams you built, results you drove.

The skill auto-detects companies from the source content. If a file is clearly about a specific role or company, create an experience section for it.

### Tier 3 — Cross-cutting

Learnings that span multiple topics or are about marketing in general. These go on the home page.

Examples: "Every marketing team I've run has the same three problems", "The single most important hire for a growth team".

### Skip

Content that isn't a marketing learning: personal notes, logistics, admin items, anything too vague to be useful.

---

## Step 3: Show what was found

Present everything, grouped by source file:

| From | Learning | Type | Goes to | Summary |
|---|---|---|---|---|
| q4-notes.md | ROAS formula | Formula | Paid advertising | Direct ROAS = ((portals × LTV) − spend) / spend |
| q4-notes.md | Built 12-person team | Finding | HubSpot (experience) | Grew demand gen team from 3 to 12 in 18 months |
| meeting-recap.md | Attribution is broken | Callout | Attribution | Last-touch attribution under-credits content by 40% |

Also note:
- Any new companies detected that will get their own experience page
- How many items were skipped and why

**Wait for the user to review.** They'll confirm, move items to different topics, or remove things. Do NOT update the artifact until they say go.

---

## Step 4: Build the artifact

### First build

1. Read `template-index.html` (ships with this repo). Never overwrite it — it stays as the blank template for reference.
2. Update the name and role from `config.json`.
3. For each topic with learnings, replace the placeholder with real content.
4. Topics with no learnings keep the "Waiting for your notes" placeholder.
5. Add experience pages for any detected companies.
6. Write the updated `index.html`.

### Update

1. Read the existing `index.html`.
2. Add each new learning into the right section of the right page.
3. If a topic page still has placeholder content, replace it with the real content.
4. If a new company is detected, add a new page and sidebar link.
5. Write the updated `index.html`.

### How learnings become components

Each learning type maps to a visual component in the artifact:

**Metric** → Stat card (the number, a label, and context). Grouped in rows of 3.

**Finding** → Bullet-style row with a checkmark icon and bold title. Green icon for especially transferable insights.

**Formula** → Monospace formula display with an explanation of how to apply it.

**Win** → Entry in the green "What worked" column.

**Loss** → Entry in the red "What didn't work" column.

**Callout** → Highlighted box for counter-intuitive or high-importance insights.

**Channel** → Row in a channel strategy table.

### Page layout order

Each topic page is organized top-to-bottom (only sections with content appear):

1. Key metrics
2. Funnel framework (if enough learnings to populate a top/mid/bottom funnel view)
3. Key learnings
4. Formulas & frameworks
5. What worked vs. what didn't
6. Key insights
7. Channel breakdown

---

## Step 5: Wrap up

After building/updating the artifact, archive processed files and record them so they're skipped on future runs.

**Local mode:**

1. Move processed files from `raw/` to `archive/` with `mv`.
2. Append each filename and date to `raw/.processed.md`.
3. Write `index.html` to the project root.

Tell the user:

> "Done! Your intelligence layer has been updated:
> - **14 learnings** added across 4 topics
> - **Demand gen**: 5 new learnings
> - **Paid**: 3 new learnings
> - **Leadership**: 4 new learnings
> - **HubSpot** experience page created (2 learnings)
> - Your processed files have been moved to `archive/`
> - Open `index.html` in your browser to see it"

**Drive mode:**

1. Copy each processed file to the `archive` subfolder in Drive using the `copy_file` tool.
2. Append each file ID, filename, and date to `.processed.md` in the Drive root folder.
3. Write `index.html` to the Drive root folder using the Google Drive MCP's `create_file` tool with:
   - `name`: `index.html`
   - `textContent`: the full HTML content
   - `contentMimeType`: `text/html`
   - `disableConversionToGoogleType`: `true`
   - `parents`: the root folder ID from `config.json`

If `index.html` already exists in the Drive root folder, update it rather than creating a duplicate.

Tell the user:

> "Done! Your intelligence layer has been updated in Google Drive:
> - **14 learnings** added across 4 topics
> - **Demand gen**: 5 new learnings
> - **Paid**: 3 new learnings
> - **Leadership**: 4 new learnings
> - **HubSpot** experience page created (2 learnings)
> - Your files have been copied to `archive/` — you can delete them from `raw/` to keep it clean
> - Open `index.html` from your Drive folder to see it"

---

## Edge cases

- If a file is too large to process in one pass, read it in chunks and extract learnings from each chunk.
- If a learning fits multiple topics, pick the most actionable one. Don't duplicate across topics.
- If the artifact gets very large (100KB+), let the user know.
- If the user's files contain no marketing learnings, say: "I didn't find any marketing learnings in these files. Try adding notes about strategies you've used, results you've seen, or frameworks you've developed."
