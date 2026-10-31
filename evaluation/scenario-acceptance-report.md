# Cloak real-world scenario acceptance

- Date: 2026-07-16
- Status: **complete**
- Scenarios scored: 5/5
- Primary web-enabled auxiliary-linkage privacy passes: 0/5 (64 candidates per scenario; 5 web-search tool calls)
- Auxiliary-free fictional-persona protocol passes: 5/5
- Worst-case closed-world privacy passes: 0/5
- Strict utility equivalence: 1/5; mean score 94.0/100
- Same practical value: 2/5
- Exact restoration for tokens used in answers: 5/5
- Clean restoration diagnostics: 5/5
- Whole-workflow acceptance: 0/5
- Honest blocks: realistic 5/5, closed-world 5/5; inference-edit utility degradations: 0; surrogate-only utility misses: 0
- Execution remote calls, including superseded runs: 109
- Call provenance: current results 35; archived attempts 60; failed/interrupted attempts 5; legacy pre-history calls 9

This suite tests the whole private-person workflow, not just controller correctness or public-figure re-identification. GPT-5.6 performs the real task on raw and sanitized documents using the same task prompt; a separate strict GPT-5.6 judgment compares substantive value after local restoration.

The primary privacy tier is now a stronger evaluation stressor: GPT-5.6 gets web search plus a 64-person synthetic population standing in for broker, employer, merchant, and case-record attributes. The former auxiliary-free fictional-persona test remains a separate tier, and the unchanged four-person roster remains the explicit worst-case controller stress tier.

A `surrogate_only_utility_miss` means the paired answer failed the strict utility gate even though Cloak made no inference edit and preserved the document's substantive facts. The failure still counts, but it is not attributed to deleted task content. Natural surrogate effects and one-shot answer variance remain possible causes.

## Outcomes

| Scenario | Web + 64 linkage | Auxiliary-free | Closed-world stress | Utility | Restore | Boundary |
|---|---|---|---|---:|---|---|
| `contract-employment-raleigh` | re-id rank 1 · blocked | not re-id · verified | re-id rank 1 · blocked | 94/100 · partial | exact | realistic_privacy_block |
| `medical-complex-care` | re-id rank 1 · blocked | not re-id · verified | re-id rank 1 · blocked | 100/100 · equivalent | exact | realistic_privacy_block |
| `immigration-asylum-declaration` | re-id rank 1 · blocked | not re-id · verified | re-id rank 1 · blocked | 88/100 · partial | exact | realistic_privacy_block |
| `financial-credit-statement` | re-id rank 1 · blocked | not re-id · verified | re-id rank 1 · blocked | 96/100 · partial | exact | realistic_privacy_block |
| `hr-retaliation-complaint` | re-id rank 1 · blocked | not re-id · verified | re-id rank 1 · blocked | 92/100 · partial | exact | realistic_privacy_block |

## Scenario detail

### contract-employment-raleigh

- Source: [SEC-filed employment agreement clauses](https://www.sec.gov/Archives/edgar/data/1534154/000161577417000380/s105242_ex10-3.htm); `public_document_adaptation`.
- User task: Review this employment agreement from the employee's perspective. Identify the five most employee-unfavorable clauses, explain the practical risk of each, identify important protections that are missing or one-sided, and give a prioritized list of negotiation questions. Do not claim to provide legal advice.
- Primary web-enabled linkage privacy: re-identified `True`; rank `1`; final `linkage_blocked`; population 64; 1 GPT-5.6 call and 1 web-search tool calls.
- Auxiliary-free fictional-persona tier: re-identified `False`; rank `None`; final `run_passed`; 0 edits and 2 attacker calls.
- Closed-world stress: re-identified `True`; rank `1`; final `run_blocked`; 0 edits and 1 attacker calls.
- Closed-world conflicting facts: This agreement is entered into on 8 September 2025 between Meadow Clinical Systems LLC, with offices in Raleigh, North Carolina, and Cameron Perry, employee number EMP-69241, residing at 240 Oak Terrace, Stonehaven, NC 16438. | 8 September 2025 | September 2025 | 2025 | Ms. Perry will serve as Director of Product Operations for the employer's clinical workflow business..
- Utility: **94/100 (partial)** — coverage 38/40, advice 28/30, actionability 20/20, factual consistency 8/10. Same practical value: `False`.
- Critical omissions: ['It does not recommend standard confidentiality exclusions for information that is public, previously known to the employee, independently developed, or lawfully obtained from third parties, which the raw-document answer identifies as important protections.', 'It omits change-in-control protections, including severance or vesting treatment if a sale or reorganization leads to termination or a diminished role.', 'It does not request a prompt post-termination determination identifying whether and how the employer intends to enforce the restrictive covenant, leaving the employee with avoidable uncertainty when seeking new work.', 'It does not seek contractual reimbursement of employee legal fees for negotiating the agreement or successfully enforcing it, addressing only preservation of statutory fee-shifting rights.', 'It does not expressly acknowledge the existing favorable provision allowing legally protected reports to government agencies.'].
- Substantive distortions: ['The statement that there is “no express preservation” of agency rights or protected reporting is misleading because Section 3 expressly permits legally protected reports to government agencies, even though the arbitration clause itself does not restate that protection.', 'The heading “No noncompete consideration” is unsupported. The document provides employment compensation and a signing bonus; whether legally sufficient or separately required consideration supports the covenant depends on governing law. The accurate criticism is that there is no pay during the restricted period.', 'The answer recommends a noncompete of “no more than 6–12 months,” but the existing restriction is already 12 months. Unlike the raw answer’s request to shorten the period, this formulation could leave the duration unchanged, although the answer otherwise proposes substantial narrowing.'].
- Judge rationale: The restored answer identifies all required core findings: the automatic-renewal trap, the highly broad 12-month noncompete, asymmetric arbitration and court access, no-fault signing-bonus repayment, outside-hours invention assignment without a prior-inventions schedule, and the need to negotiate severance, good reason, fee shifting, governing law, and narrower restrictions. Its practical explanations and prioritized questions are highly actionable. It nevertheless loses some material secondary protections from the reference and introduces two factual overstatements concerning protected reporting and noncompete consideration. Those deficiencies prevent strict equivalence in practical value, despite the answer’s strong overall coverage.
- Restore: exact for all 6 surrogate occurrences used in the answer: `True`; restored 6. Missing source tokens not used by the answer: 0; duplicated references 0; mutated 0; unknown 0.
- Boundary expectation: The clauses, not the employee's identity, are the substance; this is the expected sweet spot.
- Boundary handling observed: `realistic_privacy_block`.

### medical-complex-care

- Source: Synthetic longitudinal clinical summary; `realistic_constructed`.
- User task: Prepare a concise, prioritized list of questions this patient should take to the next specialist appointment. Flag medication-safety issues, missing monitoring, interactions between the conditions, and symptoms that may require urgent attention. Distinguish questions from medical conclusions.
- Primary web-enabled linkage privacy: re-identified `True`; rank `1`; final `linkage_blocked`; population 64; 1 GPT-5.6 call and 1 web-search tool calls.
- Auxiliary-free fictional-persona tier: re-identified `False`; rank `None`; final `run_passed`; 0 edits and 2 attacker calls.
- Closed-world stress: re-identified `True`; rank `1`; final `run_blocked`; 0 edits and 1 attacker calls.
- Closed-world conflicting facts: Ms. Mercer is a 34-year-old Arabic medical interpreter in the Detroit area with ileocolonic Crohn's disease diagnosed after hospitalization in 2021. | 34-year | 2021 | adalimumab 40 mg every other week | She currently uses adalimumab 40 mg every other week and reports that abdominal cramping returns two to three days before each dose..
- Utility: **100/100 (equivalent)** — coverage 40/40, advice 30/30, actionability 20/20, factual consistency 10/10. Same practical value: `True`.
- Critical omissions: none.
- Substantive distortions: none.
- Judge rationale: The restored answer preserves all required findings and the practical value of the reference answer. It prioritizes TB clarification during anti-TNF therapy, retrieval or repetition of chest imaging, infectious-disease involvement, biologic-management questions, and liver-safe TB treatment planning. It addresses elevated liver enzymes and right-upper-quadrant symptoms, Crohn’s control and overdue colonoscopy, anemia workup, ibuprofen safety, coordinated pregnancy planning without abrupt adalimumab cessation, vaccine review with avoidance or special timing of live vaccines, required CBC/liver/inflammatory monitoring, infection warning signs, and ownership of follow-up. It clearly separates questions from labeled safety information and provides actionable urgent-care thresholds. Added items such as pyridoxine with isoniazid, breastfeeding planning, and obstruction symptoms are reasonable questions or safety guidance and do not contradict the source.
- Restore: exact for all 6 surrogate occurrences used in the answer: `True`; restored 6. Missing source tokens not used by the answer: 0; duplicated references 0; mutated 0; unknown 0.
- Boundary expectation: The condition, treatment, language role, and pregnancy-planning stack is both medically necessary and potentially identifying within a small community.
- Boundary handling observed: `realistic_privacy_block`.

### immigration-asylum-declaration

- Source: Synthetic asylum declaration work draft; `realistic_constructed`.
- User task: Review this draft immigration declaration for internal consistency and evidentiary gaps. Identify the facts that most strongly support the claim, dates or details that need clarification, corroborating evidence to request, and passages whose generalization would materially weaken the case. Do not decide legal eligibility or provide a legal conclusion.
- Primary web-enabled linkage privacy: re-identified `True`; rank `1`; final `linkage_blocked`; population 64; 1 GPT-5.6 call and 1 web-search tool calls.
- Auxiliary-free fictional-persona tier: re-identified `False`; rank `None`; final `run_passed`; 0 edits and 2 attacker calls.
- Closed-world stress: re-identified `True`; rank `1`; final `run_blocked`; 0 edits and 1 attacker calls.
- Closed-world conflicting facts: I worked as a payroll analyst for the municipality of San Isidro. | In May 2023 I noticed that three workers listed on an irrigation-modernization contract shared bank details with relatives of the contractor's local manager. | May 2023 | 2023 | On 14 August 2023, two men stopped me near the eastern bus depot after work..
- Utility: **88/100 (partial)** — coverage 34/40, advice 27/30, actionability 18/20, factual consistency 9/10. Same practical value: `False`.
- Critical omissions: ['It does not directly request an explanation for why the declarant remained in the country until January 2024 after the June threat, August assault, and later Puerto Nieve inquiry. Asking for the departure date, intervening incidents, and living arrangements does not fully address the required delayed-departure explanation or connect it to her financial support of her mother and daughter.', 'It does not squarely identify the uncorroborated inference that the attackers were affiliated with the contractor. It requests the attackers’ words and cautions generally about limits of knowledge, but does not expressly require a clearer basis or corroboration for linking the contractor, caller, attackers, stranger, and municipal actors.', 'It misses the potential inconsistency between being described as a “payroll analyst” and the stranger’s claim that she “configured” the three-stage approval system. The declaration should clarify whether she designed, modified, installed, configured, or merely operated that system.', 'It repeats or preserves the allegation that police did not contact the audit office without asking how the declarant knows this. The account should distinguish confirmed knowledge from an inference based on lack of follow-up.', 'The discussion of the two returns does not ask whether the declarant’s mother and daughter accompanied her or remained in San Isidro, a fact that could materially illuminate both the returns and the delayed departure.'].
- Substantive distortions: ['The final section refers to the clinic’s “inability to identify the attackers,” whereas the source establishes only that the clinic letter does not identify them. Silence in a record should not be characterized as an affirmative inability.'].
- Judge rationale: The sanitized answer is comprehensive and highly actionable. It preserves the core chronology, identifies the mismatch between one narrated threat and two screenshots, distinguishes treatment from the later clinic-letter date, requests the principal documentary and witness evidence, and correctly emphasizes the distinctive three-stage payroll clue underlying the failed relocation account. It also preserves appropriate uncertainty about who disclosed the work information. However, it omits several material consistency concerns caught by the reference answer, especially the payroll-analyst/configuration discrepancy and the declarant’s basis for claiming police never contacted the audit office. More importantly under the required findings, it does not explicitly demand an explanation for the delayed January departure or directly confront the weakly supported contractor-attacker nexus. Those omissions mean it does not provide quite the same practical value as the raw-document answer, despite otherwise strong coverage.
- Restore: exact for all 4 surrogate occurrences used in the answer: `True`; restored 4. Missing source tokens not used by the answer: 0; duplicated references 0; mutated 0; unknown 0.
- Boundary expectation: The rare chronology and local institutions are the evidence. Generalizing them enough to defeat a roster attacker can materially weaken the requested legal-document review.
- Boundary handling observed: `realistic_privacy_block`.

### financial-credit-statement

- Source: [CFPB sample credit-card statement](https://files.consumerfinance.gov/f/documents/cfpb_building_block_activities_sample-credit-card-statement_handout.pdf); `public_document_adaptation`.
- User task: Review this credit-card statement for the cardholder. Explain the most important fees, interest, utilization, payment risks, and unusual spending patterns; identify any transaction that merits verification; and give a prioritized, numerically grounded action plan for the next billing cycle. Do not provide investment advice.
- Primary web-enabled linkage privacy: re-identified `True`; rank `1`; final `linkage_blocked`; population 64; 1 GPT-5.6 call and 1 web-search tool calls.
- Auxiliary-free fictional-persona tier: re-identified `False`; rank `None`; final `run_passed`; 0 edits and 2 attacker calls.
- Closed-world stress: re-identified `True`; rank `1`; final `run_blocked`; 0 edits and 1 attacker calls.
- Closed-world conflicting facts: Credit limit: $8,000.00 | $8,000.00 | 14 Jun — Laurent Hotel, Montreal — $612.00 | 14 Jun | $612.00.
- Utility: **96/100 (partial)** — coverage 38/40, advice 29/30, actionability 19/20, factual consistency 10/10. Same practical value: `True`.
- Critical omissions: ['Both answers omit the explicitly required recommendation to check or enable fraud/transaction alerts, particularly while reviewing the duplicate ferry charges and Montreal hotel charge.'].
- Substantive distortions: none.
- Judge rationale: The restored answer preserves essentially all of the raw answer’s practical value and accurately covers 88.7% utilization, limited available credit, minimum-payment and high-APR risks, the $39 late fee and $74.18 interest charge, the fee-waiver request, duplicate ferry charges, Montreal hotel verification, the $159.30 transaction-summary discrepancy, dominant travel spending, autopay, reduced spending, and several numerically grounded payment targets. Its arithmetic is consistent with the source, and added qualifications about daily-balance interest, grace periods, and trailing interest are appropriately framed. The only material strict-coverage failure is that neither answer tells the cardholder to check or enable fraud alerts, despite that being an explicit required action-plan element.
- Restore: exact for all 5 surrogate occurrences used in the answer: `True`; restored 5. Missing source tokens not used by the answer: 0; duplicated references 0; mutated 0; unknown 0.
- Boundary expectation: Amounts and transaction risks matter; the cardholder's identity does not.
- Boundary handling observed: `realistic_privacy_block`.

### hr-retaliation-complaint

- Source: [EEOC sample charge and non-retaliation notice structure](https://www.eeoc.gov/sites/default/files/migrated_files/employers/respondent_portal_users_guide_1-28-2016.pdf); `realistic_constructed_from_public_guidance`.
- User task: Review this workplace complaint as a neutral employee-side preparation memo. Build a chronology, separate direct observations from inference, identify the strongest and weakest retaliation or discrimination indicators, list documents and witnesses to preserve, and propose focused questions for HR or counsel. Do not decide whether a law was violated.
- Primary web-enabled linkage privacy: re-identified `True`; rank `1`; final `linkage_blocked`; population 64; 1 GPT-5.6 call and 1 web-search tool calls.
- Auxiliary-free fictional-persona tier: re-identified `False`; rank `None`; final `run_passed`; 0 edits and 2 attacker calls.
- Closed-world stress: re-identified `True`; rank `1`; final `run_blocked`; 0 edits and 1 attacker calls.
- Closed-world conflicting facts: I am a route-analytics lead in the Chicago operation. | returned from parental leave | I returned from parental leave on 3 February 2026. | 3 February 2026 | February 2026.
- Utility: **92/100 (partial)** — coverage 37/40, advice 27/30, actionability 19/20, factual consistency 9/10. Same practical value: `False`.
- Critical omissions: ['It does not expressly state the important chronology-based limitation that the 20 February promotion denial preceded the 2 March HR report and therefore cannot, on the current facts, be retaliation for that report.', 'It does not squarely ask whether any performance concerns or adverse performance reasons were documented before parental leave, a required factual gap for evaluating the before-and-after record.', 'The witness list does not separately identify the HR representative who communicated the “greater schedule flexibility” explanation, the forecast recipient, or other analytics leads who could address comparator scheduling and discipline practices.', 'The counsel questions omit calendaring potentially applicable external filing deadlines and do not expressly ask about collective-bargaining provisions, both of which appeared in the raw-document answer and may be time-sensitive.'].
- Substantive distortions: ['The answer twice characterizes the missing-data message as having been sent before the forecast deadline. The source establishes only that it was sent the prior day; it does not establish its relation to the actual deadline.'].
- Judge rationale: The sanitized answer is otherwise highly substantive: it supplies the required chronology, treats the manager’s new-baby comment as a witnessed firsthand report requiring context, distinguishes observation from inference, accurately describes temporal proximity as suggestive rather than conclusive, and provides extensive preservation and interview questions covering scorecards, criteria, comparators, Slack, schedules, warning drafts, metadata, and decision-maker knowledge. However, the omitted pre-complaint-retaliation qualification and pre-leave performance-documentation question are material, and the unsupported forecast-deadline characterization could affect analysis of the warning. The narrower witness and deadline coverage also makes it modestly less useful than the raw answer.
- Restore: exact for all 6 surrogate occurrences used in the answer: `True`; restored 6. Missing source tokens not used by the answer: 0; duplicated references 0; mutated 0; unknown 0.
- Boundary expectation: The chronology and evidence categories matter, while the complainant's identity and employer name can be hidden.
- Boundary handling observed: `realistic_privacy_block`.

## Interpretation limits

- All protected subjects and auxiliary-roster entries are fictional private personas.
- Public documents supply clause/layout realism only; sensitive medical, immigration, and workplace facts are synthetic.
- The web-enabled tier still uses synthetic people and a synthetic candidate population. It is a more realistic linkage stress test, not a measured population anonymity rate or a substitute for testing with consented people who have real public and commercial traces.
- The auxiliary-free tier is retained for comparability but remains weak evidence for fictional people.
- The four-person closed-world roster is deliberately adversarial and is not a population estimate.
- The raw task answer, restored answer, and roster leave the machine only in this explicit synthetic evaluation harness; this is not a product egress path.
- GPT-5.6 generated both task answers and judged utility. The structured rubric and required-findings list make the comparison strict, but it is not an independent human or cross-model judgment.
- Restoration is scored on surrogate occurrences the task answer actually uses. A task model may legitimately omit an email or account number; those are reported as missing source tokens rather than treated as incorrect substitution.
- Medical and legal scenario outputs evaluate task preservation only and are not medical or legal advice.
