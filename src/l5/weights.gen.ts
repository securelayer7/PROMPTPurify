/**
 * CODEGEN OUTPUT — do not edit by hand.
 * Regenerate: `node scripts/train-l5a.mjs` (after `npm run build`).
 *
 * V3: L2-regularized logistic regression, class-balanced, trained fully
 * offline in JS on the REAL-DATA deterministic split (training/split_real.py
 * via scripts/corpus-real.mjs). Standardization uses TRAIN stats only.
 * PROBABILISTIC and advisory only — see README "L5a". Never clears a block.
 */
export const L5A_VERSION = "l5a-v3-real-2026-05-17";
export const L5A_FEATURE_NAMES: string[] = ["char_entropy","role_token_density","override_verb_ratio","override_target_proximity","script_mix_frac","log_len","token_count_log","mean_token_len","uppercase_ratio","punct_ratio","longest_nonspace_run","negation_near_safety","second_person_density","fiction_frame_hits","l4_families_fired","has_url","b64_run_norm","l4_rule_count"];
export const L5A_MEAN: number[] = [4.10988863, 0.00169946, 0.01187843, 0.94168587, 0.24028117, 1.89054594, 1.12112386, 7.10539015, 0.08535519, 0.02829903, 0.21127722, 0.00094594, 0.02875009, 0.00854839, 0.09137097, 0.00395161, 0.21569624, 0.09669355];
export const L5A_STD: number[] = [0.34190921, 0.12717153, 0.03781533, 0.20765676, 0.40284058, 0.51418013, 0.52132719, 29.67654901, 0.19501108, 0.0423479, 1.77394811, 0.01187163, 0.13635281, 0.09550117, 0.34024146, 0.06273753, 2.36533139, 0.37449584];
export const L5A_WEIGHTS: number[] = [-0.1662921, 0.00146727, 0.55298438, -0.44009255, -0.74729546, 0.39552554, 0.06997858, 0.13474369, 0.20268, 0.09302222, 0.13824503, 0.19670842, 0.04797375, -0.19365482, 0.47317698, 0.03023126, 0.14534104, 0.44173782];
export const L5A_INTERCEPT = -1.10797811;
