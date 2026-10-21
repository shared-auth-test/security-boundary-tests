import 'dart:async';

import 'package:rxdart/rxdart.dart';

import 'auth_lifecycle.dart';
import 'auth_lifecycle_hooks.dart';

/// A replaying [ValueStream] whose synchronous value is read from the lifecycle
/// machine itself rather than from a second mutable cache.
///
/// The wrapped source emits the current lifecycle value at subscription time,
/// so a dormant period with no Rx listeners cannot leave a stale replay value.
final class _CurrentValueStream<T> extends StreamView<T>
    implements ValueStream<T> {
  _CurrentValueStream(super.stream, this._current);

  final T Function() _current;

  @override
  T get value => _current();

  @override
  T? get valueOrNull => _current();

  @override
  bool get hasValue => true;

  @override
  Object get error => throw ValueStreamError.hasNoError();

  @override
  Object? get errorOrNull => null;

  @override
  bool get hasError => false;

  @override
  StackTrace? get stackTrace => null;

  @override
  StreamNotification<T>? get lastEventOrNull =>
      StreamNotification<T>.data(_current());
}

/// RxDart projection of [AuthLifecycleHooks].
///
/// State and capability streams replay the machine's *current* value to every
/// new listener, even if the machine changed while no Rx listener existed.
/// Lifecycle ownership remains in the dependency-free hooks/machine layer; the
/// Rx adapter never introduces another mutable authentication state authority.
final class RxAuthLifecycle {
  RxAuthLifecycle([AuthLifecycleHooks? hooks])
      : hooks = hooks ?? AuthLifecycleHooks(),
        _ownsHooks = hooks == null {
    transitions$ = this.hooks.transitions.share();

    state$ = _CurrentValueStream<AuthLifecycleState>(
      this.hooks.stateChanges().distinct(),
      () => this.hooks.state,
    );
    allowsAuthenticatedApi$ = _CurrentValueStream<bool>(
      this
          .hooks
          .stateChanges()
          .map((state) => state.allowsAuthenticatedApi)
          .distinct(),
      () => this.hooks.state.allowsAuthenticatedApi,
    );
    allowsPrivilegedApi$ = _CurrentValueStream<bool>(
      this
          .hooks
          .stateChanges()
          .map((state) => state.allowsPrivilegedApi)
          .distinct(),
      () => this.hooks.state.allowsPrivilegedApi,
    );
    operationInFlight$ = _CurrentValueStream<bool>(
      this
          .hooks
          .stateChanges()
          .map((state) => state.operationInFlight)
          .distinct(),
      () => this.hooks.state.operationInFlight,
    );
  }

  final AuthLifecycleHooks hooks;
  final bool _ownsHooks;

  late final Stream<AuthTransition> transitions$;
  late final ValueStream<AuthLifecycleState> state$;
  late final ValueStream<bool> allowsAuthenticatedApi$;
  late final ValueStream<bool> allowsPrivilegedApi$;
  late final ValueStream<bool> operationInFlight$;

  AuthLifecycleState get state => hooks.state;

  AuthTransition dispatch(AuthLifecycleEvent event) => hooks.dispatch(event);

  Future<AuthTransition> dispatchAsync(AuthLifecycleEvent event) {
    return hooks.dispatchAsync(event);
  }

  Future<void> close() {
    return _ownsHooks ? hooks.close() : Future<void>.value();
  }
}
