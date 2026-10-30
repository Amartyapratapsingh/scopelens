# ScopeLens UI reference audit

Inspected 28 September 2026. Reference: https://nexchat.framer.website/.
User supplied a licensed Nexchat brief and prioritized ScopeLens home and dashboard, with no authentication UI. This document records the first design pass; no frontend implementation is claimed yet. Follow the brief's staged delivery: design system first, then small implementation batches after “continue.”

## Design read

Security SaaS for website owners: Nexchat's dark, spacious presentation, silver display type, blue illumination, rounded product frames, adapted to evidence-backed website assessments. Match the supplied reference rather than applying unrelated visual conventions.

## Measured design system

| Property | Reference measurement |
|---|---|
| Display family | Manrope, weight 600 |
| Body/navigation | Inter Tight, weights 400, 500, 600 |
| Wordmark | Geist 600, 23 px / 27.6 px, tracking -0.23 px |
| Desktop H1 | 68 px / 68 px, tracking -2.72 px |
| Mobile H1 | 40 px / 40 px, tracking -1.6 px |
| Desktop H2 | 60 px / 64 px, tracking -3 px |
| Mobile H2 | 32 px / 41 px, tracking -1.6 px |
| Body | 16 px / 24 px, tracking -0.16 px |
| Background / surface | #000000 / #0f0f0f |
| White / secondary / neutral | #ffffff / #a0a0a0 / #2f2f2f |
| Additional source tokens | #282441, #d9d9d999 |
| Heading fill | Gradient from #787878 at top to #ffffff at bottom; parent computed black is not the painted text color |
| Desktop content | 1280 px at 1440 viewport, 80 px side gutters |
| Mobile content | 20 px side gutters; 350 px usable at 390 |
| Section separation | 160 px desktop, 80 px mobile |
| Heading-to-card gap | 80 px desktop, 40 px mobile |
| Card grid gap | 20 px |
| Card padding | Common 32 px; some visual cards have 100 px top padding |
| Corners | Cards 20 px, product frame 24 px, pill buttons/forms |
| Main responsive boundaries | Desktop 1440+, tablet 810–1439, mobile below 810; a few text styles also use 1200 |

At 768 and 390 px the page had no horizontal overflow. Blue glows and CTA treatment include image assets; no single solid blue token was found. Exact asset mapping, shadow inventory, contrast checks and 360 px verification remain part of implementation. Fonts are exposed through font-face declarations; self-host the appropriate licensed font files when building.

## Reference pages and section order

| Navigation page | Observed sections, in order |
|---|---|
| Home | Hero and product preview; logo ticker; workflow bento; three-step process plus CTA; tools; pricing; testimonials; FAQ; articles; closing CTA and footer |
| About | Story hero; problem/metrics; responsibility and trust; differentiators; team; FAQ; closing CTA/footer |
| Features | Feature hero; workflow bento; tools; FAQ; closing CTA/footer |
| Pricing | Plans hero and three pricing cards; FAQ; closing CTA/footer |
| Blog | Blog library/card listing; closing CTA/footer |
| Career | Careers hero; workplace introduction; openings; testimonials; closing CTA/footer |
| Contact (nav CTA) | Contact introduction and form; closing CTA/footer |

These pages were opened and their section headings inspected. Detailed motion/visual reproduction of secondary pages is not complete and is outside the immediate two-page implementation priority.

## ScopeLens page mapping

### Home

1. Navigation: ScopeLens, capabilities, how it works, reports, Open dashboard.
2. Hero: “Find vulnerabilities in your website.” Supporting copy about evidence, coverage and practical fixes. Website URL input replaces the email capture.
3. Product preview: ScopeLens scan, findings and report surface, clearly marked as a preview if illustrative.
4. Capability strip replaces unsupported customer-count/logo claims.
5. Workflow bento: discover the surface, assess supported checks, verify evidence.
6. Three-step flow: provide URL and scope → run assessment → review findings and scorecard.
7. Report and findings-assistant showcase, using the reference's tools-card treatment.
8. FAQ about coverage, AI, uncertainty, reports and retesting.
9. Closing scan CTA and compact footer.

Pricing, testimonials, customer logos and blog claims require real product content before publication; do not invent customers, prices, guarantees or findings. Maintain the visual rhythm using product-focused sections.

### Dashboard

The reference embeds a dashboard image; it does not supply a functioning dashboard page. Extend its visual language into ScopeLens's actual application:

- Sidebar and responsive navigation.
- Website URL intake and assessment controls.
- Recent scans with live progress and clear partial/failed states.
- Scorecard with coverage and score-unavailable reasons.
- Findings table with severity/status filters and evidence/remediation details.
- HTML/JSON report downloads and retest actions.
- Findings assistant panel grounded in the selected scan, with references to its evidence. Do not simulate a live model response as real.

No login/signup UI in this phase. Preserve backend authorization; do not expose credentials or weaken access checks to remove a screen. An unavailable session/data source must have an explicit unconnected state; any demonstration must be clearly labeled. Preserve the existing typed API adapter and supported assessment actions during redesign.

## Motion inventory

| Element | Trigger | Observed states | Measured timing / status |
|---|---|---|---|
| Hero title | Page load | opacity ~0→1; translateY 80→0; scale .9→1 | 2000 ms, delay 200 ms, cubic-bezier(.16,1,.3,1); captured on two reloads |
| Hero supporting text | Page load | Same fade/translate/scale | 2000 ms, delay 300 ms, same easing; captured twice |
| Product preview | Page load | opacity ~0→1; translateY 150→0 | 900 ms, delay 600 ms, sampled spring-shaped keyframes; nominal linear timing does not mean linear visual movement |
| Logo ticker | Continuous loop | translateX 0→-2848 px | 47,466.67 ms linear at measured desktop content width; preserve speed when replacing content |
| Workflow cards | Scroll entry | Hidden starting state at translateY 50 px recorded | Full transition timing/stagger still needs capture at the card intersection before implementation |
| Remaining cards, CTA hovers, FAQ, mobile menu | Scroll/hover/click | Interaction inspection pending | Do not claim reference-exact durations until measured |

Use one motion implementation and shared timing tokens. Reduced motion removes travel and loops. Content remains visible when JavaScript fails. Product dashboard status changes should favor readability over marketing entrance effects.

## Build sequence

1. Tokens, fonts, shared buttons/navigation, homepage hero and product preview.
2. Homepage capability/process/report sections, FAQ and footer.
3. Dashboard overview, scans and scorecard.
4. Finding details, exports, assistant panel and API connection states.
5. Compare at 1440, 768, 390 and overflow-check 360; keyboard, reduced-motion and functional checks.

Retain the existing React/TypeScript Vite app and add Tailwind through its Vite integration. A framework migration is unnecessary for these two screens. First implementation batch begins after the user continues, as requested in their supplied brief.

## Evidence

Raw CSS/animation captures and desktop/mobile screenshots are stored under `docs/ui-reference/`. Some lower-page motion could not be fully characterized in this first pass; this is recorded above rather than replaced with guessed timing.
