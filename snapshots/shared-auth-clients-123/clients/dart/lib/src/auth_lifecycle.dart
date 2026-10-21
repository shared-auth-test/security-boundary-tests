// GENERATED from formal/auth-lifecycle.json; do not edit by hand.
// Contract SHA-256: a1948e7cab6fdc1fd226061c73faf42b32f9f35642996fc930dfae0c25229659

/// Every modeled authentication state. No arbitrary or unknown state exists.
enum AuthLifecycleState {
  signedOut('signedOut', false, false, false, false),
  authorizing('authorizing', false, true, false, false),
  exchanging('exchanging', false, true, false, false),
  unavailable('unavailable', false, false, false, false),
  authenticated('authenticated', true, false, true, false),
  refreshing('refreshing', true, true, false, false),
  stepUpRequired('stepUpRequired', true, false, true, false),
  steppingUp('steppingUp', true, true, false, false),
  authenticatedAal2('authenticatedAal2', true, false, true, true),
  degraded('degraded', true, false, false, false),
  signingOut('signingOut', true, true, false, false),
  locked('locked', false, false, false, false);

  const AuthLifecycleState(
    this.wireName,
    this.hasCredential,
    this.operationInFlight,
    this.allowsAuthenticatedApi,
    this.allowsPrivilegedApi,
  );

  final String wireName;
  final bool hasCredential;
  final bool operationInFlight;
  final bool allowsAuthenticatedApi;
  final bool allowsPrivilegedApi;
}

/// Inputs accepted by the formal application lifecycle.
enum AuthLifecycleEvent {
  startSignIn('startSignIn'),
  receiveAuthorizationCode('receiveAuthorizationCode'),
  authenticationSucceeded('authenticationSucceeded'),
  authenticationRejected('authenticationRejected'),
  transientFailure('transientFailure'),
  cancel('cancel'),
  startRefresh('startRefresh'),
  refreshSucceeded('refreshSucceeded'),
  refreshRejected('refreshRejected'),
  requireStepUp('requireStepUp'),
  startStepUp('startStepUp'),
  stepUpSucceeded('stepUpSucceeded'),
  stepUpRejected('stepUpRejected'),
  recover('recover'),
  startSignOut('startSignOut'),
  signOutSucceeded('signOutSucceeded'),
  signOutFailed('signOutFailed'),
  detectCredentialCorruption('detectCredentialCorruption');

  const AuthLifecycleEvent(this.wireName);
  final String wireName;
}

/// Credential-vault work the application must perform atomically with a transition.
enum AuthLifecycleEffect {
  none('none'),
  acquireCredential('acquireCredential'),
  retainCredential('retainCredential'),
  clearCredential('clearCredential'),
  clearCredentialAndRetryRevocation('clearCredentialAndRetryRevocation'),
  retryWithoutCredential('retryWithoutCredential'),
  rejected('rejected');

  const AuthLifecycleEffect(this.wireName);
  final String wireName;
}

/// A total transition result: accepted transitions advance the state; every
/// undefined State x Event pair is an explicit, non-mutating rejection.
final class AuthTransition {
  const AuthTransition._({
    required this.previousState,
    required this.event,
    required this.currentState,
    required this.effect,
    required this.accepted,
    this.rejectionReason,
  });

  final AuthLifecycleState previousState;
  final AuthLifecycleEvent event;
  final AuthLifecycleState currentState;
  final AuthLifecycleEffect effect;
  final bool accepted;
  final String? rejectionReason;

  bool get stateChanged => previousState != currentState;
}

final class _AuthTransitionTarget {
  const _AuthTransitionTarget(this.state, this.effect);
  final AuthLifecycleState state;
  final AuthLifecycleEffect effect;
}

/// Pure generated transition relation shared by Flutter mobile and desktop apps.
abstract final class AuthLifecycle {
  static const String contractFingerprint = 'a1948e7cab6fdc1fd226061c73faf42b32f9f35642996fc930dfae0c25229659';

  static const Map<String, _AuthTransitionTarget> _accepted =
      <String, _AuthTransitionTarget>{
    'signedOut|startSignIn': _AuthTransitionTarget(AuthLifecycleState.authorizing, AuthLifecycleEffect.none),
    'signedOut|detectCredentialCorruption': _AuthTransitionTarget(AuthLifecycleState.locked, AuthLifecycleEffect.clearCredential),
    'authorizing|receiveAuthorizationCode': _AuthTransitionTarget(AuthLifecycleState.exchanging, AuthLifecycleEffect.none),
    'authorizing|authenticationRejected': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.none),
    'authorizing|transientFailure': _AuthTransitionTarget(AuthLifecycleState.unavailable, AuthLifecycleEffect.retryWithoutCredential),
    'authorizing|cancel': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.none),
    'exchanging|authenticationSucceeded': _AuthTransitionTarget(AuthLifecycleState.authenticated, AuthLifecycleEffect.acquireCredential),
    'exchanging|authenticationRejected': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.none),
    'exchanging|transientFailure': _AuthTransitionTarget(AuthLifecycleState.unavailable, AuthLifecycleEffect.retryWithoutCredential),
    'exchanging|cancel': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.none),
    'unavailable|recover': _AuthTransitionTarget(AuthLifecycleState.authorizing, AuthLifecycleEffect.none),
    'unavailable|cancel': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.none),
    'unavailable|startSignOut': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.none),
    'unavailable|detectCredentialCorruption': _AuthTransitionTarget(AuthLifecycleState.locked, AuthLifecycleEffect.clearCredential),
    'authenticated|startRefresh': _AuthTransitionTarget(AuthLifecycleState.refreshing, AuthLifecycleEffect.retainCredential),
    'authenticated|requireStepUp': _AuthTransitionTarget(AuthLifecycleState.stepUpRequired, AuthLifecycleEffect.retainCredential),
    'authenticated|transientFailure': _AuthTransitionTarget(AuthLifecycleState.degraded, AuthLifecycleEffect.retainCredential),
    'authenticated|startSignOut': _AuthTransitionTarget(AuthLifecycleState.signingOut, AuthLifecycleEffect.retainCredential),
    'authenticated|detectCredentialCorruption': _AuthTransitionTarget(AuthLifecycleState.locked, AuthLifecycleEffect.clearCredential),
    'refreshing|refreshSucceeded': _AuthTransitionTarget(AuthLifecycleState.authenticated, AuthLifecycleEffect.retainCredential),
    'refreshing|refreshRejected': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.clearCredential),
    'refreshing|transientFailure': _AuthTransitionTarget(AuthLifecycleState.degraded, AuthLifecycleEffect.retainCredential),
    'refreshing|startSignOut': _AuthTransitionTarget(AuthLifecycleState.signingOut, AuthLifecycleEffect.retainCredential),
    'refreshing|detectCredentialCorruption': _AuthTransitionTarget(AuthLifecycleState.locked, AuthLifecycleEffect.clearCredential),
    'stepUpRequired|startStepUp': _AuthTransitionTarget(AuthLifecycleState.steppingUp, AuthLifecycleEffect.retainCredential),
    'stepUpRequired|startRefresh': _AuthTransitionTarget(AuthLifecycleState.refreshing, AuthLifecycleEffect.retainCredential),
    'stepUpRequired|transientFailure': _AuthTransitionTarget(AuthLifecycleState.degraded, AuthLifecycleEffect.retainCredential),
    'stepUpRequired|cancel': _AuthTransitionTarget(AuthLifecycleState.authenticated, AuthLifecycleEffect.retainCredential),
    'stepUpRequired|startSignOut': _AuthTransitionTarget(AuthLifecycleState.signingOut, AuthLifecycleEffect.retainCredential),
    'stepUpRequired|detectCredentialCorruption': _AuthTransitionTarget(AuthLifecycleState.locked, AuthLifecycleEffect.clearCredential),
    'steppingUp|stepUpSucceeded': _AuthTransitionTarget(AuthLifecycleState.authenticatedAal2, AuthLifecycleEffect.retainCredential),
    'steppingUp|stepUpRejected': _AuthTransitionTarget(AuthLifecycleState.stepUpRequired, AuthLifecycleEffect.retainCredential),
    'steppingUp|transientFailure': _AuthTransitionTarget(AuthLifecycleState.stepUpRequired, AuthLifecycleEffect.retainCredential),
    'steppingUp|cancel': _AuthTransitionTarget(AuthLifecycleState.authenticated, AuthLifecycleEffect.retainCredential),
    'steppingUp|startSignOut': _AuthTransitionTarget(AuthLifecycleState.signingOut, AuthLifecycleEffect.retainCredential),
    'steppingUp|detectCredentialCorruption': _AuthTransitionTarget(AuthLifecycleState.locked, AuthLifecycleEffect.clearCredential),
    'authenticatedAal2|startRefresh': _AuthTransitionTarget(AuthLifecycleState.refreshing, AuthLifecycleEffect.retainCredential),
    'authenticatedAal2|requireStepUp': _AuthTransitionTarget(AuthLifecycleState.authenticatedAal2, AuthLifecycleEffect.retainCredential),
    'authenticatedAal2|transientFailure': _AuthTransitionTarget(AuthLifecycleState.degraded, AuthLifecycleEffect.retainCredential),
    'authenticatedAal2|startSignOut': _AuthTransitionTarget(AuthLifecycleState.signingOut, AuthLifecycleEffect.retainCredential),
    'authenticatedAal2|detectCredentialCorruption': _AuthTransitionTarget(AuthLifecycleState.locked, AuthLifecycleEffect.clearCredential),
    'degraded|recover': _AuthTransitionTarget(AuthLifecycleState.refreshing, AuthLifecycleEffect.retainCredential),
    'degraded|startSignOut': _AuthTransitionTarget(AuthLifecycleState.signingOut, AuthLifecycleEffect.retainCredential),
    'degraded|detectCredentialCorruption': _AuthTransitionTarget(AuthLifecycleState.locked, AuthLifecycleEffect.clearCredential),
    'signingOut|signOutSucceeded': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.clearCredential),
    'signingOut|signOutFailed': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.clearCredentialAndRetryRevocation),
    'signingOut|detectCredentialCorruption': _AuthTransitionTarget(AuthLifecycleState.locked, AuthLifecycleEffect.clearCredential),
    'locked|recover': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.clearCredential),
    'locked|startSignOut': _AuthTransitionTarget(AuthLifecycleState.signedOut, AuthLifecycleEffect.clearCredential),
  };

  static AuthTransition transition(
    AuthLifecycleState state,
    AuthLifecycleEvent event,
  ) {
    final target = _accepted['${state.wireName}|${event.wireName}'];
    if (target == null) {
      return AuthTransition._(
        previousState: state,
        event: event,
        currentState: state,
        effect: AuthLifecycleEffect.rejected,
        accepted: false,
        rejectionReason:
            '${event.wireName} is not valid while ${state.wireName}',
      );
    }
    return AuthTransition._(
      previousState: state,
      event: event,
      currentState: target.state,
      effect: target.effect,
      accepted: true,
    );
  }
}

/// Serial application coordinator. Restore a non-transient state only after
/// the platform credential vault has been verified and reconciled.
final class AuthLifecycleMachine {
  AuthLifecycleMachine._(this._state);

  factory AuthLifecycleMachine() =>
      AuthLifecycleMachine._(AuthLifecycleState.signedOut);

  factory AuthLifecycleMachine.restore(AuthLifecycleState state) {
    if (state.operationInFlight) {
      throw ArgumentError.value(
        state,
        'state',
        'cannot restore an in-flight authentication operation',
      );
    }
    return AuthLifecycleMachine._(state);
  }

  AuthLifecycleState _state;
  AuthLifecycleState get state => _state;

  AuthTransition dispatch(AuthLifecycleEvent event) {
    final outcome = AuthLifecycle.transition(_state, event);
    if (outcome.accepted) _state = outcome.currentState;
    return outcome;
  }
}
