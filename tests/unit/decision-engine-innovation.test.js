'use strict';

const { decideValidation } = require('../../packages/validation-service/src/decision-engine');

test('adaptive decision adds action, confidence and strict threshold under risky conditions', () => {
    const decision = decideValidation({
        signatureValid: true,
        decryptionValid: true,
        contextValid: false,
        replayValid: true,
        riskScore: 35,
        contextDrift: 45
    });

    expect(decision.allow).toBe(false);
    expect(decision.reason).toBe('context_mismatch');
    expect(decision.threshold).toBe(99);
    expect(decision.action).toBe('reauthenticate_user');
    expect(decision.confidence).toBeLessThan(0.5);
});

test('clean signals produce allow action with high confidence', () => {
    const decision = decideValidation({
        signatureValid: true,
        decryptionValid: true,
        contextValid: true,
        replayValid: true,
        riskScore: 95,
        contextDrift: 0
    });

    expect(decision.allow).toBe(true);
    expect(decision.reason).toBe('ok');
    expect(decision.action).toBe('allow');
    expect(decision.confidence).toBeGreaterThanOrEqual(0.5);
});
