'use strict';

const {
    logAnomaly,
    getAnomalyInsights
} = require('../../packages/auth-server/src/anomaly-detector');

test('getAnomalyInsights returns deep analytics structure with recommendations', () => {
    const marker = `unit_insights_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

    logAnomaly(marker, { ip: '10.10.10.10', uid: 'insight-user' });
    logAnomaly(marker, { ip: '10.10.10.10', uid: 'insight-user' });
    logAnomaly(marker, { ip: '10.10.10.10', uid: 'insight-user' });

    const insights = getAnomalyInsights({ windowMs: 60 * 60 * 1000, topN: 6 });

    expect(insights).toBeDefined();
    expect(insights.totals.events).toBeGreaterThan(0);
    expect(insights.distributions).toBeDefined();
    expect(Array.isArray(insights.distributions.topTypes)).toBe(true);
    expect(insights.distributions.topTypes.some((item) => item.type === marker)).toBe(true);
    expect(['rising', 'falling', 'stable']).toContain(insights.trend.direction);
    expect(Array.isArray(insights.recommendations)).toBe(true);
    expect(insights.recommendations.length).toBeGreaterThan(0);
});
