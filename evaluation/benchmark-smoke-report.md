# Cloak benchmark smoke set

- Date: 2026-07-16
- Status: **complete reported smoke set**
- Headline: **raw 100% → naive redaction 60% → Cloak 33%**
- Sample: 15 English synthetic cases; 15/15 raw-identifiable
- Attacker: fixed cross-family GPT-5.6 adapter; returned models: gpt-5.6-sol
- Final-condition remote calls represented: 80
- Total execution calls, including superseded fixture revisions: 206

This is a deliberately small, author-generated smoke set—not a validated benchmark, release bar, or demo blocker. The aspirational target is a near-zero final re-identification rate; the table reports the observed point gap to 0% and a 95% Wilson interval so a small sample cannot masquerade as validation.

## Overall result

| Condition | Re-identified | Rate | 95% Wilson interval | Gap to 0% aspiration |
|---|---:|---:|---:|---:|
| Raw synthetic document | 15/15 | 100% | 80%–100% | +100.0 pp |
| Presidio + opaque direct identifiers | 9/15 | 60% | 36%–80% | +60.0 pp |
| Cloak core loop | 5/15 | 33% | 15%–58% | +33.3 pp |

Against the naive baseline, Cloak changed the observed rate by -26.7 percentage points. This sample is too small to treat that difference as validated.

Raw and naive conditions use one medium-effort attack each. Cloak uses the production core loop: medium-effort discovery/post-edit attacks. The stack-aware controller can retire up to two grounded clues per attack and seven total edits, then requires a separate high-effort holdout. Causal deepening is disabled.

## Same-case controller change

The pre-fix run on these exact fixtures and the same GPT-5.6 attacker was **raw 100% → naive 60% → Cloak 53% (8/15)**. The stack-aware controller reduced Cloak to **33% (5/15)**, a 20-point improvement. Single-clue re-identification fell from 3/5 to 1/5; aggregate re-identification fell from 5/5 to 4/5. Direct-PII controls remained 0/5.

This is still a failed near-zero aspiration, especially for aggregate cases. The one aggregate pass shows that the controller can exhaust a removable clue stack. Each of the four residual aggregate cases has a must-preserve sentence that itself describes the subject's distinctive arc; Cloak blocks instead of deleting that pinned substance or claiming a pass.

## Breakdown by difficulty

| Difficulty | Condition | Re-identified | Rate |
|---|---|---:|---:|
| Direct-PII control | Raw | 5/5 | 100% |
| Direct-PII control | Naive | 0/5 | 0% |
| Direct-PII control | Cloak | 0/5 | 0% |
| Single distinctive clue | Raw | 5/5 | 100% |
| Single distinctive clue | Naive | 4/5 | 80% |
| Single distinctive clue | Cloak | 1/5 | 20% |
| Aggregate quasi-identifiers | Raw | 5/5 | 100% |
| Aggregate quasi-identifiers | Naive | 5/5 | 100% |
| Aggregate quasi-identifiers | Cloak | 4/5 | 80% |

## Per-case outcomes

| Case | Protected subject | Difficulty | Raw | Naive | Cloak | Full-loop outcome | Calls | Substance-bound |
|---|---|---|---|---|---|---|---:|---|
| `direct-ada-lovelace` | Ada Lovelace | Direct-PII control | yes · rank 1 | no | no | run_passed | 4 | no |
| `direct-toni-morrison` | Toni Morrison | Direct-PII control | yes · rank 1 | no | no | run_passed | 4 | no |
| `direct-michael-jordan` | Michael Jordan | Direct-PII control | yes · rank 1 | no | no | run_passed | 4 | no |
| `direct-jane-goodall` | Jane Goodall | Direct-PII control | yes · rank 1 | no | no | run_passed | 4 | no |
| `direct-hayao-miyazaki` | Hayao Miyazaki | Direct-PII control | yes · rank 1 | no | no | run_passed | 4 | no |
| `distinctive-alan-turing` | Alan Turing | Single distinctive clue | yes · rank 1 | yes · rank 1 | no | run_passed | 6 | yes |
| `distinctive-malala-yousafzai` | Malala Yousafzai | Single distinctive clue | yes · rank 1 | yes · rank 1 | no | run_passed | 8 | yes |
| `distinctive-chesley-sullenberger` | Chesley Sullenberger | Single distinctive clue | yes · rank 1 | no | no | run_passed | 4 | yes |
| `distinctive-maryam-mirzakhani` | Maryam Mirzakhani | Single distinctive clue | yes · rank 1 | yes · rank 1 | no | run_passed | 6 | yes |
| `distinctive-wangari-maathai` | Wangari Maathai | Single distinctive clue | yes · rank 1 | yes · rank 1 | yes · rank 1 | run_blocked | 5 | yes |
| `aggregate-satya-nadella` | Satya Nadella | Aggregate quasi-identifiers | yes · rank 1 | yes · rank 1 | no | run_passed | 6 | yes |
| `aggregate-michelle-yeoh` | Michelle Yeoh | Aggregate quasi-identifiers | yes · rank 1 | yes · rank 1 | yes · rank 2 | run_blocked | 6 | yes |
| `aggregate-temple-grandin` | Temple Grandin | Aggregate quasi-identifiers | yes · rank 1 | yes · rank 1 | yes · rank 1 | run_blocked | 7 | yes |
| `aggregate-ta-nehisi-coates` | Ta-Nehisi Coates | Aggregate quasi-identifiers | yes · rank 1 | yes · rank 1 | yes · rank 1 | run_blocked | 7 | yes |
| `aggregate-demis-hassabis` | Demis Hassabis | Aggregate quasi-identifiers | yes · rank 1 | yes · rank 1 | yes · rank 1 | run_blocked | 5 | yes |

## Residual Cloak re-identifications

- `distinctive-wangari-maathai`: rank 1, run_blocked, 2 accepted edits. Evidence: ['The subject led a regional environmental initiative.', 'The subject described an organizational evolution.', 'The final version should describe the starting need, how participants coordinated repeated work, and two broad effects on civic participation.', 'The case study may generalize the profession, country, city, organization, and activity while preserving a problem, organizing method, and community result.'].
- `aggregate-michelle-yeoh`: rank 2, run_blocked, 7 accepted edits. Evidence: ['The requested rewrite must preserve the transition from dance training to screen performance, explain how movement skills transferred between fields, and avoid naming productions or awards.', 'The subject ended their career due to physical pain.', 'The subject pursued professional artistic activities overseas while young.', 'The subject participated in an earlier competition prior to professional activity.'].
- `aggregate-temple-grandin`: rank 1, run_blocked, 7 accepted edits. Evidence: ['The summary must retain the connection between animal behavior and facility design, but no one item should dominate the explanation.', 'The identity is exposed by the stack of childhood history, ranch experience, education route, teaching location, and a particular engineering approach.', 'The subject encountered early communication difficulties during childhood.', 'The subject engaged in field research then began instructing others.', 'The subject worked on local agricultural initiatives.'].
- `aggregate-ta-nehisi-coates`: rank 1, run_blocked, 7 accepted edits. Evidence: ['The analysis must keep the letter-to-a-son structure and explain how reporting, family address, and historical argument interact.', 'The subject produced work in the form of correspondence.', 'The subject worked across various local organizations.', 'The subject spent their early years in a region focused on literature.'].
- `aggregate-demis-hassabis`: rank 1, run_blocked, 4 accepted edits. Evidence: ['The editor must preserve the progression from games to neuroscience to artificial intelligence.', 'The subject developed expertise in competitive games during childhood and received recognition for designing a popular video game during youth.', 'No direct title is needed; the combination of childhood competition, teenage game design, education, doctoral field, city, and company aim creates the re-identification risk.', 'studied the subject of interest, and founded a regional institution in the technical field.'].

## Aggregate core-loop traces

- `aggregate-satya-nadella`: 4 accepted edits; final `run_passed` (Passed the configured GPT-5.6 verification protocol); cumulative edit distance 29.3%. Patches: `He studied electrical engineering in Manipal before completing graduate work in Milwaukee.` → `The subject completed earlier technical training at one institution.`; `Colleagues later heard him use cricket as a management metaphor after he joined a Redmond software company in the early 1990s.` → `The subject used sports metaphors at an organization.`; `The subject grew up in Hyderabad in a household shaped by public service and Sanskrit scholarship.` → `The subject was raised in a region influenced by civic duty.`; `The subject used sports metaphors at an organization.` → `The subject applied personal interests to professional activities.`. Residual subject evidence: [].
- `aggregate-michelle-yeoh`: 7 accepted edits; final `run_blocked` (Verification stopped safely); cumulative edit distance 37.1%. Patches: `The subject grew up in Ipoh and moved to Britain as a teenager for ballet training.` → `The subject trained professionally abroad during adolescence.`; `A back injury closed the professional dance route.` → `The subject ended their career due to physical pain.`; `A national beauty title then preceded commercial work and physically demanding Hong Kong films.` → `The subject won a regional pageant before acting.`; `The subject trained professionally abroad during adolescence.` → `The subject pursued professional artistic activities overseas while young.`; `Each detail is broad on its own, but the birthplace, training move, injury, title, and film market form a near-unique stack.` → `The subject completed an unusual sequence of events.`; `The subject won a regional pageant before acting.` → `The subject participated in an earlier competition prior to professional activity.`; `The subject ended their career due to physical pain.` → `The subject stopped participating in a regional activity.`. Residual subject evidence: ['The requested rewrite must preserve the transition from dance training to screen performance, explain how movement skills transferred between fields, and avoid naming productions or awards.', 'The subject ended their career due to physical pain.', 'The subject pursued professional artistic activities overseas while young.', 'The subject participated in an earlier competition prior to professional activity.'].
- `aggregate-temple-grandin`: 7 accepted edits; final `run_blocked` (Edit cap reached); cumulative edit distance 27.5%. Patches: `Her applied work designed curved livestock handling systems around animal behavior.` → `The subject developed regional livestock management projects.`; `She studied animal science across Arizona and Illinois before teaching in Colorado.` → `The subject pursued regional studies then taught elsewhere.`; `The subject experienced delayed speech as a child in Boston and later spent formative time on a relative's cattle ranch.` → `The subject had early communication delays then worked on a family farm.`; `The subject pursued regional studies then taught elsewhere.` → `The subject engaged in field research then began instructing others.`; `The subject had early communication delays then worked on a family farm.` → `The subject faced initial language challenges before engaging in agricultural work.`; `The subject developed regional livestock management projects.` → `The subject worked on local agricultural initiatives.`; `The subject faced initial language challenges before engaging in agricultural work.` → `The subject encountered early communication difficulties during childhood.`. Residual subject evidence: ['The summary must retain the connection between animal behavior and facility design, but no one item should dominate the explanation.', 'The identity is exposed by the stack of childhood history, ranch experience, education route, teaching location, and a particular engineering approach.', 'The subject encountered early communication difficulties during childhood.', 'The subject engaged in field research then began instructing others.', 'The subject worked on local agricultural initiatives.'].
- `aggregate-ta-nehisi-coates`: 7 accepted edits; final `run_blocked` (Edit cap reached); cumulative edit distance 32.7%. Patches: `A subsequent book was structured as a letter to his teenage son.` → `The subject wrote a later work in the form of correspondence.`; `He attended Howard University without completing a degree, moved through newspaper jobs, and later wrote a national magazine essay on reparations.` → `The subject worked in journalism before writing an article.`; `The writer grew up in West Baltimore in a household centered on books and Black political history.` → `The subject spent their early years in a region focused on literature.`; `The subject wrote a later work in the form of correspondence.` → `The subject created an earlier project using personal communication.`; `The subject worked in journalism before writing an article.` → `The subject engaged in regional media work.`; `The subject created an earlier project using personal communication.` → `The subject produced work in the form of correspondence.`; `The subject engaged in regional media work.` → `The subject worked across various local organizations.`. Residual subject evidence: ['The analysis must keep the letter-to-a-son structure and explain how reporting, family address, and historical argument interact.', 'The subject produced work in the form of correspondence.', 'The subject worked across various local organizations.', 'The subject spent their early years in a region focused on literature.'].
- `aggregate-demis-hassabis`: 4 accepted edits; final `run_blocked` (No utility-bounded clue edit was available); cumulative edit distance 30.1%. Patches: `helped design a successful theme-park simulation game while still a teenager` → `received recognition for designing a popular video game during youth`; `became a strong tournament chess player as a child in north London` → `developed expertise in competitive games during childhood`; `co-founded a London research company pursuing general artificial intelligence` → `founded a regional institution in the technical field`; `He studied computer science at Cambridge, later completed doctoral work in cognitive neuroscience` → `studied the subject of interest`. Residual subject evidence: ['The editor must preserve the progression from games to neuroscience to artificial intelligence.', 'The subject developed expertise in competitive games during childhood and received recognition for designing a popular video game during youth.', 'No direct title is needed; the combination of childhood competition, teenage game design, education, doctoral field, city, and company aim creates the re-identification risk.', 'studied the subject of interest, and founded a regional institution in the technical field.'].

## Identity-is-substance flags

- `distinctive-alan-turing`: The distinctive wartime contribution is the document's main subject; removing it substantially reduces utility.
- `distinctive-malala-yousafzai`: The role, place, and attack are the narrative's central event and cannot all be removed without gutting it.
- `distinctive-chesley-sullenberger`: The landing is both the identifying clue and the operational case study being summarized.
- `distinctive-maryam-mirzakhani`: The singular award milestone is the requested article's main significance claim.
- `distinctive-wangari-maathai`: The named movement and organizing method are the substance of the requested case study.
- `aggregate-satya-nadella`: The stacked education, migration, and career path is the substance of the leadership profile.
- `aggregate-michelle-yeoh`: The unusual sequence from ballet through a pageant into action cinema is the profile's core arc.
- `aggregate-temple-grandin`: The combined life history and design practice are the educational case's substantive content.
- `aggregate-ta-nehisi-coates`: The accumulated biography and letter form are integral to the requested literary analysis.
- `aggregate-demis-hassabis`: The cross-field progression is the central thesis and extensive removal would gut the profile.

## Interpretation and limits

- Cases were authored from scratch inside the Cloak repository; no external dataset or repository was imported.
- The raw condition sends only these committed synthetic fixtures through a case-ID-only loopback route whose strict empty control body rejects document text. It is not a path for user documents and does not weaken Cloak's product boundary.
- Every full-set case had to be recovered from its raw document before its baselines were scored. A raw miss halts the runner rather than making later conditions look artificially safe.
- The naive baseline uses Presidio `PatternRecognizer` rules for direct contact/number spans plus Cloak's confirmed subject aliases, then replaces those exact values with local opaque tokens. It performs no inference.
- This is one English set, one run per condition, one attacker family, and no independent human utility rating. Prompt stochasticity and public-knowledge changes are not estimated.
- A 0% point estimate would not validate anonymity: with only 15 cases, its 95% Wilson upper bound remains material. Conversely, any residual case is a concrete controller/product finding, not a release-gate failure.
- Several profiles intentionally make identity the substance. Their flags distinguish privacy failure from the harder reality that removing the identifying story may destroy the document's purpose.
