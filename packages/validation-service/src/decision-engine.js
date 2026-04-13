'use strict';

/**
 * Weight each validation signal. The total adds up to 100.
 *
 *   Signature (HMAC)   40  — outer tamper detection
 *   Decryption (AES)   30  — inner confidentiality + epoch binding
 *   Context (fp + ctx) 20  — width-dimension environment binding
 *   Replay (rot + jti) 10  — time-dimension freshness
 */
const WEIGHTS = Object.freeze({
    signature: 40,
    decryption: 30,
    context: 20,
    replay: 10
});

/** Minimum combined score to accept a request. */
const ACCEPT_THRESHOLD = 90;

const POLICY_PROFILES = Object.freeze({
    strict: {
        baseOffset: 4,
        riskSensitivity: 1.2,
        driftSensitivity: 1.2,
        minThreshold: 90,
        maxThreshold: 99
    },
    balanced: {
        baseOffset: 0,
        riskSensitivity: 1,
        driftSensitivity: 1,
        minThreshold: 80,
        maxThreshold: 99
    },
    compat: {
        baseOffset: -10,
        riskSensitivity: 0.6,
        driftSensitivity: 0.6,
        minThreshold: 70,
        maxThreshold: 96
    }
});

let policyProfileOverride = null;

/**
 * Score the four validation signals into a 0–100 integer.
 *
 * @param {object}  signals
 * @param {boolean} signals.signatureValid
 * @param {boolean} signals.decryptionValid
 * @param {boolean} signals.contextValid
 * @param {boolean} signals.replayValid
 * @returns {number} 0–100
 */
function scoreSignals({ signatureValid, decryptionValid, contextValid, replayValid }) {
    let score = 0;
    if (signatureValid) score += WEIGHTS.signature;
    if (decryptionValid) score += WEIGHTS.decryption;
    if (contextValid) score += WEIGHTS.context;
    if (replayValid) score += WEIGHTS.replay;
    return score;
}

/**
 * Produce a machine-readable reason code for the first failing signal.
 *
 * @param {object} signals
 * @returns {string}
 */
function failureReason(signals) {
    if (!signals.signatureValid) return 'bad_signature';
    if (!signals.decryptionValid) return 'decrypt_fail';
    if (!signals.contextValid) return 'context_mismatch';
    if (!signals.replayValid) return 'replay_detected';
    return 'ok';
}

/**
 * Return all failed signal reason codes (ordered by severity priority).
 *
 * @param {object} signals
 * @returns {string[]}
 */
function failureReasons(signals) {
    const reasons = [];
    if (!signals.signatureValid) reasons.push('bad_signature');
    if (!signals.decryptionValid) reasons.push('decrypt_fail');
    if (!signals.contextValid) reasons.push('context_mismatch');
    if (!signals.replayValid) reasons.push('replay_detected');
    return reasons;
}

function normalizePolicyProfile(profile = 'balanced') {
    const value = String(profile || 'balanced').trim().toLowerCase();
    if (value === 'strict' || value === 'balanced' || value === 'compat') {
        return value;
    }
    return 'balanced';
}

function getPolicyProfile() {
    const configured = policyProfileOverride || process.env.VAULT_POLICY_PROFILE || 'balanced';
    return normalizePolicyProfile(configured);
}

function setPolicyProfile(profile) {
    policyProfileOverride = normalizePolicyProfile(profile);
    return policyProfileOverride;
}

function clearPolicyProfileOverride() {
    policyProfileOverride = null;
}

function normalizeProfileList(profiles) {
    const base = Array.isArray(profiles)
        ? profiles
        : (profiles === undefined || profiles === null
            ? Object.keys(POLICY_PROFILES)
            : [profiles]);

    const normalized = [...new Set(base.map(normalizePolicyProfile))];
    return normalized.length > 0 ? normalized : ['balanced'];
}

/**
 * Dynamically increase threshold for risky runtime contexts.
 *
 * Inputs (optional):
 *  - riskScore:    runtime trust score (0..100)
 *  - contextDrift: fingerprint drift score (0..100)
 *
 * @param {object} signals
 * @returns {number}
 */
function dynamicThreshold(signals = {}, profile = 'balanced') {
    const normalizedProfile = normalizePolicyProfile(profile);
    const cfg = POLICY_PROFILES[normalizedProfile];
    let threshold = ACCEPT_THRESHOLD + cfg.baseOffset;

    const riskScore = Number(signals.riskScore);
    const contextDrift = Number(signals.contextDrift);

    if (Number.isFinite(riskScore)) {
        if (riskScore < 60) threshold += Math.ceil(5 * cfg.riskSensitivity);
        if (riskScore < 40) threshold += Math.ceil(5 * cfg.riskSensitivity);
    }

    if (Number.isFinite(contextDrift)) {
        if (contextDrift > 20) threshold += Math.ceil(5 * cfg.driftSensitivity);
        if (contextDrift > 40) threshold += Math.ceil(5 * cfg.driftSensitivity);
    }

    return Math.max(cfg.minThreshold, Math.min(cfg.maxThreshold, threshold));
}

function confidenceScore(score, threshold) {
    const delta = score - threshold;
    const normalized = delta >= 0
        ? 0.5 + Math.min(0.5, delta / 20)
        : 0.5 - Math.min(0.5, Math.abs(delta) / 20);
    return Math.round(normalized * 100) / 100;
}

function scoreTier(score) {
    if (score >= 95) return 'excellent';
    if (score >= 85) return 'strong';
    if (score >= 70) return 'guarded';
    return 'critical';
}

function recommendedAction(reason, signals = {}, profile = 'balanced') {
    if (reason === 'ok') return 'allow';
    if (reason === 'bad_signature') return 'block_and_alert';
    if (reason === 'replay_detected') return 'terminate_session_and_alert';
    if (reason === 'decrypt_fail') return 'deny_and_rotate_keys';
    if (reason === 'context_mismatch') {
        if (profile === 'strict') return 'reauthenticate_user';
        if (profile === 'compat') return 'step_up_auth';
        return Number(signals.contextDrift || 0) > 40 ? 'reauthenticate_user' : 'step_up_auth';
    }
    if (reason === 'score_below_threshold') {
        return profile === 'compat' ? 'step_up_auth' : 'deny';
    }
    return 'deny';
}

/**
 * Run the decision engine: score all signals, compare against the acceptance
 * threshold, and return a structured verdict.
 *
 * @param {object} signals - { signatureValid, decryptionValid, contextValid, replayValid }
 * @returns {{ allow: boolean, reason: string, score: number }}
 */
function decideValidation(signals) {
    const profile = normalizePolicyProfile(signals?.policyProfile || getPolicyProfile());
    const score = scoreSignals(signals);
    const threshold = dynamicThreshold(signals, profile);
    const reasons = failureReasons(signals);
    const allow = score >= threshold;
    const reason = allow ? 'ok' : (reasons[0] || 'score_below_threshold');
    return {
        allow,
        reason,
        reasons,
        score,
        threshold,
        confidence: confidenceScore(score, threshold),
        tier: scoreTier(score),
        action: recommendedAction(reason, signals, profile),
        policyProfile: profile
    };
}

/**
 * Simulate the same signal payload against one or many policy profiles.
 *
 * @param {object} signals
 * @param {string[]|string} [profiles]
 * @returns {{ profiles: string[], matrix: Record<string, object> }}
 */
function simulatePolicyProfiles(signals, profiles) {
    const selectedProfiles = normalizeProfileList(profiles);
    const matrix = {};

    for (const profile of selectedProfiles) {
        matrix[profile] = decideValidation({ ...signals, policyProfile: profile });
    }

    return {
        profiles: selectedProfiles,
        matrix
    };
}

/**
 * Recommend an operational profile given runtime signals.
 * Returns a rationale string plus the underlying simulation matrix.
 *
 * @param {object} signals
 * @param {string[]|string} [profiles]
 * @returns {{ recommended: string, rationale: string, simulation: {profiles:string[], matrix: Record<string, object>} }}
 */
function recommendPolicyProfile(signals, profiles) {
    const simulation = simulatePolicyProfiles(signals, profiles);
    const strict = simulation.matrix.strict;
    const balanced = simulation.matrix.balanced;
    const compat = simulation.matrix.compat;

    const riskScore = Number(signals?.riskScore);
    const contextDrift = Number(signals?.contextDrift);

    if (compat && compat.allow === false) {
        return {
            recommended: 'strict',
            rationale: 'All profiles deny this signal set; strict mode is recommended for containment.',
            simulation
        };
    }

    if (strict?.allow === true && Number.isFinite(riskScore) && Number.isFinite(contextDrift) && riskScore >= 85 && contextDrift <= 15) {
        return {
            recommended: 'strict',
            rationale: 'Signals are high-confidence and stable; strict mode can be enabled without user-friction spike.',
            simulation
        };
    }

    if (strict?.allow === false && balanced?.allow === true) {
        return {
            recommended: 'balanced',
            rationale: 'Strict blocks the request but balanced allows it, providing security with lower false-deny risk.',
            simulation
        };
    }

    if (balanced?.allow === false && compat?.allow === true) {
        return {
            recommended: 'compat',
            rationale: 'Balanced denies while compat allows; choose compat for temporary continuity during elevated drift.',
            simulation
        };
    }

    return {
        recommended: 'balanced',
        rationale: 'Balanced remains the safest default trade-off for mixed traffic conditions.',
        simulation
    };
}

module.exports = {
    decideValidation,
    scoreSignals,
    failureReason,
    failureReasons,
    dynamicThreshold,
    normalizePolicyProfile,
    getPolicyProfile,
    setPolicyProfile,
    clearPolicyProfileOverride,
    confidenceScore,
    scoreTier,
    recommendedAction,
    simulatePolicyProfiles,
    recommendPolicyProfile,
    POLICY_PROFILES,
    WEIGHTS,
    ACCEPT_THRESHOLD
};
