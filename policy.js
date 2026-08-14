// Deterministic policy engine for the /release-gate endpoint.
//
// Given a request payload describing a GitHub Actions run (its workflow
// configuration, the actions it pins, and the container image it wants to
// promote), decide whether the image may be promoted, and list every rule
// that was violated if not.

const SHA_RE = /^[0-9a-f]{40}$/;

const REQUIRED_PERMISSIONS = {
  contents: 'read',
  packages: 'write',
  'id-token': 'none',
};

function checkPermissions(workflow, violations) {
  const perms = (workflow && workflow.permissions) || {};
  const keys = Object.keys(perms);
  const requiredKeys = Object.keys(REQUIRED_PERMISSIONS);

  const exact =
    keys.length === requiredKeys.length &&
    requiredKeys.every((k) => perms[k] === REQUIRED_PERMISSIONS[k]);

  if (!exact) violations.push('EXCESS_PERMISSION');
}

function checkPrTrigger(workflow, violations) {
  if (workflow && workflow.trigger === 'pull_request_target') {
    violations.push('UNSAFE_PR_TRIGGER');
  }
}

function checkTestsComplete(workflow, violations) {
  const testsPassed = workflow && workflow.testsPassed === true;
  const matrixComplete = workflow && workflow.matrixComplete === true;
  const failFastOk = workflow && workflow.failFast === false;

  if (!testsPassed || !matrixComplete || !failFastOk) {
    violations.push('TESTS_INCOMPLETE');
  }
}

function checkActionsPinned(workflow, violations) {
  const actions = (workflow && Array.isArray(workflow.actions)) ? workflow.actions : [];

  const hasMutable = actions.some((action) => {
    if (!action || typeof action !== 'object') return true;
    if (action.owner === 'actions') {
      // Actions owned by the official "actions" org may use a version tag.
      return false;
    }
    return typeof action.ref !== 'string' || !SHA_RE.test(action.ref);
  });

  if (hasMutable) violations.push('MUTABLE_ACTION');
}

function checkImage(image, violations) {
  const img = image || {};

  if (img.multiStage !== true) violations.push('SINGLE_STAGE_IMAGE');
  if (img.runsAsRoot !== false) violations.push('ROOT_RUNTIME');

  const safeSecretModes = ['none', 'buildkit'];
  if (!safeSecretModes.includes(img.secretMode)) {
    violations.push('SECRET_IN_LAYER');
  }

  if (img.criticalVulnerabilities !== 0) violations.push('CRITICAL_CVE');
  if (img.digestPinned !== true) violations.push('UNPINNED_IMAGE');
}

function checkProduction(payload, violations) {
  if (payload.target !== 'production') return;

  const validRef = payload.event === 'push' && payload.ref === 'refs/heads/main';
  if (!validRef) violations.push('INVALID_PRODUCTION_REF');

  const approved = payload.workflow && payload.workflow.environmentApproval === true;
  if (!approved) violations.push('APPROVAL_REQUIRED');
}

function evaluate(payload) {
  const body = payload && typeof payload === 'object' ? payload : {};
  const workflow = body.workflow || {};
  const image = body.image || {};

  const violations = [];

  checkPermissions(workflow, violations);
  checkPrTrigger(workflow, violations);
  checkTestsComplete(workflow, violations);
  checkActionsPinned(workflow, violations);
  checkImage(image, violations);
  checkProduction(body, violations);

  return {
    decision: violations.length === 0 ? 'promote' : 'block',
    violations,
  };
}

module.exports = { evaluate };
