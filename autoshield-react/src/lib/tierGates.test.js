import test from 'node:test';
import assert from 'node:assert/strict';

import {
  PREMIUM_FEATURES,
  normalizeTier,
  deriveTierFromUser,
  featureGateForTier,
} from './tierGates.js';

test('normalizeTier defaults invalid values to free', () => {
  assert.equal(normalizeTier(undefined), 'free');
  assert.equal(normalizeTier(''), 'free');
  assert.equal(normalizeTier('enterprise'), 'free');
  assert.equal(normalizeTier('premium'), 'premium');
});

test('deriveTierFromUser reads user tier safely', () => {
  assert.equal(deriveTierFromUser(null), 'free');
  assert.equal(deriveTierFromUser({}), 'free');
  assert.equal(deriveTierFromUser({ tier: 'premium' }), 'premium');
  assert.equal(deriveTierFromUser({ tier: 'random' }), 'free');
});

test('featureGateForTier blocks premium feature on free tier', () => {
  const gate = featureGateForTier('free', 'geoBlocking', PREMIUM_FEATURES);
  assert.equal(gate.allowed, false);
  assert.equal(gate.tier, 'premium');
});

test('featureGateForTier allows premium feature on premium tier', () => {
  const gate = featureGateForTier('premium', 'geoBlocking', PREMIUM_FEATURES);
  assert.equal(gate.allowed, true);
  assert.equal(gate.tier, 'premium');
});

test('featureGateForTier allows unknown feature by default', () => {
  const gate = featureGateForTier('free', 'unknownFeature', PREMIUM_FEATURES);
  assert.equal(gate.allowed, true);
  assert.equal(gate.label, 'unknownFeature');
});
