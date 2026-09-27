import 'dart:async';

import 'auth_lifecycle.dart';

/// Dependency-free lifecycle hooks shared by Flutter, native Dart and RxDart.
///
/// Rejected transitions are delivered to transition observers, but only an
/// accepted state change is delivered to state observers. All adapters consume
/// the same [AuthLifecycleMachine] and therefore cannot create a second auth
/// state authority.
final class AuthLifecycleHooks {
  AuthLifecycleHooks([AuthLifecycleMachine? machine])
      : _machine = machine ?? AuthLifecycleMachine();

  final AuthLifecycleMachine _machine;
  final StreamController<AuthTransition> _transitionController =
      StreamController<AuthTransition>.broadcast(sync: true);
  final StreamController<AuthLifecycleState> _stateController =
      StreamController<AuthLifecycleState>.broadcast(sync: true);
  var _closed = false;

  AuthLifecycleState get state => _machine.state;

  Stream<AuthTransition> get transitions => _transitionController.stream;

  Stream<AuthLifecycleState> stateChanges({bool emitCurrent = true}) {
    if (!emitCurrent) return _stateController.stream;

    // Subscribe to future state changes before emitting the current snapshot.
    // An async* `yield state; yield* changes` implementation can lose a
    // synchronous transition dispatched by the first listener callback before
    // the broadcast source has been subscribed.
    return Stream<AuthLifecycleState>.multi((controller) {
      final subscription = _stateController.stream.listen(
        controller.add,
        onError: controller.addError,
        onDone: controller.close,
      );
      controller.onCancel = subscription.cancel;
      controller.add(state);
    });
  }

  AuthTransition dispatch(AuthLifecycleEvent event) {
    if (_closed) {
      throw StateError('auth lifecycle hooks are closed');
    }
    final outcome = _machine.dispatch(event);
    _transitionController.add(outcome);
    if (outcome.stateChanged) {
      _stateController.add(outcome.currentState);
    }
    return outcome;
  }

  Future<AuthTransition> dispatchAsync(AuthLifecycleEvent event) {
    return Future<AuthTransition>.sync(() => dispatch(event));
  }

  StreamSubscription<AuthTransition> onTransition(
    void Function(AuthTransition transition) listener,
  ) {
    return transitions.listen(listener);
  }

  StreamSubscription<AuthLifecycleState> onState(
    void Function(AuthLifecycleState state) listener, {
    bool emitCurrent = true,
  }) {
    return stateChanges(emitCurrent: emitCurrent).listen(listener);
  }

  Future<AuthLifecycleState> waitForState(
    bool Function(AuthLifecycleState state) predicate, {
    Duration? timeout,
  }) {
    final future = stateChanges().firstWhere(predicate);
    return timeout == null ? future : future.timeout(timeout);
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _transitionController.close();
    await _stateController.close();
  }
}
