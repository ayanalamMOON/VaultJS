'use strict';

const {
    logAnomaly,
    getAnomalyPressure,
    getAnomalyStats
} = require('../../packages/auth-server/src/anomaly-detector');

test('anomaly pressure increases as events are logged', () => {
    const beforePressure = getAnomalyPressure();
    const beforeStats = getAnomalyStats();

    logAnomaly('unit_anomaly_pressure', { ip: '9.9.9.9', uid: 'u-pressure' });
    logAnomaly('unit_anomaly_pressure', { ip: '9.9.9.9', uid: 'u-pressure' });

    const afterPressure = getAnomalyPressure();
    const afterStats = getAnomalyStats();

    expect(afterPressure.score).toBeGreaterThan(beforePressure.score);
    expect(afterPressure.total).toBeGreaterThanOrEqual(beforePressure.total + 2);
    expect(afterStats.recentEvents).toBeGreaterThanOrEqual(beforeStats.recentEvents + 2);
});
