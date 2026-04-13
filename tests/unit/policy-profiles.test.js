'use strict';

const {
    decideValidation,
    getPolicyProfile,
    setPolicyProfile,
    clearPolicyProfileOverride,
    simulatePolicyProfiles,
    recommendPolicyProfile
} = require('../../packages/validation-service/src/decision-engine');

afterEach(() => {
    clearPolicyProfileOverride();
});

test('strict policy is harder than balanced and compat for the same signals', () => {
    const signals = {
        signatureValid: true,
        decryptionValid: true,
        contextValid: false,
        replayValid: true,
        riskScore: 70,
        contextDrift: 25
    };

    setPolicyProfile('strict');
    const strictDecision = decideValidation(signals);

    setPolicyProfile('balanced');
    const balancedDecision = decideValidation(signals);

    setPolicyProfile('compat');
    const compatDecision = decideValidation(signals);

    expect(strictDecision.threshold).toBeGreaterThan(balancedDecision.threshold);
    expect(balancedDecision.threshold).toBeGreaterThan(compatDecision.threshold);
    expect(strictDecision.action).toBe('reauthenticate_user');
    expect(compatDecision.action).toBe('step_up_auth');
});

test('policy profile can be overridden explicitly per decision call', () => {
    setPolicyProfile('compat');

    const decision = decideValidation({
        signatureValid: true,
        decryptionValid: true,
        contextValid: false,
        replayValid: true,
        riskScore: 90,
        contextDrift: 0,
        policyProfile: 'strict'
    });

    expect(decision.policyProfile).toBe('strict');
    expect(decision.action).toBe('reauthenticate_user');
});

test('invalid profile falls back to balanced', () => {
    setPolicyProfile('definitely-not-valid');
    expect(getPolicyProfile()).toBe('balanced');
});

test('simulatePolicyProfiles returns matrix for all profiles', () => {
    const simulation = simulatePolicyProfiles({
        signatureValid: true,
        decryptionValid: true,
        contextValid: false,
        replayValid: true,
        riskScore: 50,
        contextDrift: 20
    });

    expect(simulation.profiles).toEqual(expect.arrayContaining(['strict', 'balanced', 'compat']));
    expect(simulation.matrix.strict).toBeDefined();
    expect(simulation.matrix.balanced).toBeDefined();
    expect(simulation.matrix.compat).toBeDefined();
});

test('recommendPolicyProfile returns rationale and recommended profile', () => {
    const recommendation = recommendPolicyProfile({
        signatureValid: true,
        decryptionValid: true,
        contextValid: false,
        replayValid: true,
        riskScore: 55,
        contextDrift: 28
    });

    expect(['strict', 'balanced', 'compat']).toContain(recommendation.recommended);
    expect(typeof recommendation.rationale).toBe('string');
    expect(recommendation.rationale.length).toBeGreaterThan(0);
    expect(recommendation.simulation.matrix.balanced).toBeDefined();
});
