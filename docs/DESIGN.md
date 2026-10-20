# Incident desk design

The working object is an incident record. The register remains visible while an analyst moves between its timeline, decision, draft and shared telemetry. Colour marks meaning: violet `#59457c` for active work, slate `#263147` for text, pale blue `#eef1f7` for the workspace, green `#0e685f` for local status, amber `#8d470e` for review notices. System sans typography keeps long forms readable without remote font requests. A compact checkpoint strip keeps the recorded deadline visible without dominating the timeline; it is labelled conditional and distinguishes practice records.

Desktop uses a narrow incident register and two unequal work columns. Mobile stacks the panels, collapses the incident register and scrolls the navigation independently. Native controls, labels, focus outlines, a skip link, live result messages and printable views support keyboard and small-screen use. No motion, remote assets or invented operational metrics.


## Final interaction refinements

The layout favours a compact incident register, a modest conditional clock, local feedback, contextual source disclosures and a deliberate evidence ledger. At 1100px and below, observations become labelled stacked records. The ledger remains a named, keyboard-focusable region. Wide screens cap the work area and form widths. Header actions wrap with enlarged text; primary controls and disclosures have 44px minimum targets. System fonts require no network font request or bundled font licence; fallback rendering is tested separately.

Dirty forms are scoped by incident and form in browser session storage. A checklist or another form's save cannot discard them. A submitted draft clears only if no newer edit has replaced it. Explicit Discard restores that form's saved state. Late record-selection results cannot replace a more recently selected case. Browser Back preserves the view, search and recorded scroll position. Closing the native dialog returns focus; full rerenders restore field/checklist focus where applicable.

The print document is generated from saved incident data, including draft fields and collapsed chronology details. It labels the saved-state boundary; unsaved browser edits are excluded. The runbook has a separate printable layout. JSON exports retain machine-readable evidence.


## Clutter and visibility pass

The register uses a selected left rule and count instead of another row of rounded cards. A collapsed mobile register keeps the active incident close to the top of the page. The conditional checkpoint uses a pale strip with one violet edge; typography separates its countdown and due date. Timeline headings name the event (record opened, analyst note, evidence reference, changed fields), while the checklist reports completed actions. Form results appear beside the action rather than repeating a visible banner at the top. Empty state has one direction and no repeated practice button. Work sections use small corners and subtle top dividers; controls keep their 44px targets. The header grows to fit doubled text rather than relying on a fixed height.
