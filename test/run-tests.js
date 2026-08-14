const assert = require('node:assert');
const { evaluate } = require('../policy');

let passed = 0;

function sortedEqual(actual, expected, label) {
  const a = [...actual].sort();
  const e = [...expected].sort();
  assert.deepStrictEqual(a, e, label);
  passed += 1;
}

function basePayload(overrides = {}) {
  return {
    target: 'preview',
    event: 'pull_request',
    ref: 'refs/heads/feature-x',
    workflow: {
      trigger: 'pull_request',
      permissions: { contents: 'read', packages: 'write', 'id-token': 'none' },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [{ owner: 'actions', name: 'checkout', ref: 'v4' }],
      ...(overrides.workflow || {}),
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: 'none',
      criticalVulnerabilities: 0,
      digestPinned: true,
      ...(overrides.image || {}),
    },
    ...Object.fromEntries(Object.entries(overrides).filter(([k]) => k !== 'workflow' && k !== 'image')),
  };
}

// 1. A fully safe preview/PR payload promotes cleanly.
{
  const result = evaluate(basePayload());
  assert.strictEqual(result.decision, 'promote');
  sortedEqual(result.violations, [], 'safe payload should have no violations');
}

// 2. A fully safe production payload also promotes.
{
  const payload = basePayload({
    target: 'production',
    event: 'push',
    ref: 'refs/heads/main',
    workflow: { environmentApproval: true },
  });
  const result = evaluate(payload);
  assert.strictEqual(result.decision, 'promote');
  sortedEqual(result.violations, [], 'safe production payload should have no violations');
}

// 3. Excess permission scope.
{
  const payload = basePayload({
    workflow: { permissions: { contents: 'read', packages: 'write', 'id-token': 'none', actions: 'write' } },
  });
  sortedEqual(evaluate(payload).violations, ['EXCESS_PERMISSION'], 'extra scope should be caught');
}

// 4. Wrong permission value.
{
  const payload = basePayload({ workflow: { permissions: { contents: 'write', packages: 'write', 'id-token': 'none' } } });
  sortedEqual(evaluate(payload).violations, ['EXCESS_PERMISSION'], 'wrong scope value should be caught');
}

// 5. pull_request_target is always unsafe.
{
  const payload = basePayload({ workflow: { trigger: 'pull_request_target' } });
  sortedEqual(evaluate(payload).violations, ['UNSAFE_PR_TRIGGER'], 'pull_request_target should be blocked');
}

// 6. Tests not passed / matrix incomplete / failFast true.
{
  sortedEqual(evaluate(basePayload({ workflow: { testsPassed: false } })).violations, ['TESTS_INCOMPLETE']);
  sortedEqual(evaluate(basePayload({ workflow: { matrixComplete: false } })).violations, ['TESTS_INCOMPLETE']);
  sortedEqual(evaluate(basePayload({ workflow: { failFast: true } })).violations, ['TESTS_INCOMPLETE']);
}

// 7. Third-party action must be pinned to a full 40-char lowercase SHA.
{
  const payload = basePayload({
    workflow: { actions: [{ owner: 'someorg', name: 'some-action', ref: 'v1.2.3' }] },
  });
  sortedEqual(evaluate(payload).violations, ['MUTABLE_ACTION']);
}

// 8. Third-party action pinned to a full SHA is fine.
{
  const payload = basePayload({
    workflow: { actions: [{ owner: 'someorg', name: 'some-action', ref: 'a'.repeat(40) }] },
  });
  sortedEqual(evaluate(payload).violations, []);
}

// 9. actions/* may use a version tag.
{
  const payload = basePayload({
    workflow: { actions: [{ owner: 'actions', name: 'setup-node', ref: 'v4' }] },
  });
  sortedEqual(evaluate(payload).violations, []);
}

// 10. Image hardening failures, one at a time.
{
  sortedEqual(evaluate(basePayload({ image: { multiStage: false } })).violations, ['SINGLE_STAGE_IMAGE']);
  sortedEqual(evaluate(basePayload({ image: { runsAsRoot: true } })).violations, ['ROOT_RUNTIME']);
  sortedEqual(evaluate(basePayload({ image: { secretMode: 'arg' } })).violations, ['SECRET_IN_LAYER']);
  sortedEqual(evaluate(basePayload({ image: { secretMode: 'copy' } })).violations, ['SECRET_IN_LAYER']);
  sortedEqual(evaluate(basePayload({ image: { criticalVulnerabilities: 3 } })).violations, ['CRITICAL_CVE']);
  sortedEqual(evaluate(basePayload({ image: { digestPinned: false } })).violations, ['UNPINNED_IMAGE']);
}

// 11. secretMode "buildkit" is safe.
{
  sortedEqual(evaluate(basePayload({ image: { secretMode: 'buildkit' } })).violations, []);
}

// 12. Production requires push to refs/heads/main.
{
  const payload = basePayload({
    target: 'production',
    event: 'pull_request',
    ref: 'refs/heads/main',
    workflow: { environmentApproval: true },
  });
  sortedEqual(evaluate(payload).violations, ['INVALID_PRODUCTION_REF']);
}

{
  const payload = basePayload({
    target: 'production',
    event: 'push',
    ref: 'refs/heads/develop',
    workflow: { environmentApproval: true },
  });
  sortedEqual(evaluate(payload).violations, ['INVALID_PRODUCTION_REF']);
}

// 13. Production requires environmentApproval.
{
  const payload = basePayload({
    target: 'production',
    event: 'push',
    ref: 'refs/heads/main',
    workflow: { environmentApproval: false },
  });
  sortedEqual(evaluate(payload).violations, ['APPROVAL_REQUIRED']);
}

// 14. Multi-failure payload combines every applicable violation.
{
  const payload = {
    target: 'production',
    event: 'pull_request',
    ref: 'refs/heads/feature',
    workflow: {
      trigger: 'pull_request_target',
      permissions: { contents: 'write', packages: 'write', 'id-token': 'write' },
      testsPassed: false,
      matrixComplete: false,
      failFast: true,
      actions: [{ owner: 'someorg', name: 'some-action', ref: 'main' }],
      environmentApproval: false,
    },
    image: {
      multiStage: false,
      runsAsRoot: true,
      secretMode: 'copy',
      criticalVulnerabilities: 2,
      digestPinned: false,
    },
  };
  sortedEqual(evaluate(payload).violations, [
    'EXCESS_PERMISSION',
    'UNSAFE_PR_TRIGGER',
    'TESTS_INCOMPLETE',
    'MUTABLE_ACTION',
    'SINGLE_STAGE_IMAGE',
    'ROOT_RUNTIME',
    'SECRET_IN_LAYER',
    'CRITICAL_CVE',
    'UNPINNED_IMAGE',
    'INVALID_PRODUCTION_REF',
    'APPROVAL_REQUIRED',
  ]);
}

console.log(`${passed} assertions passed.`);
