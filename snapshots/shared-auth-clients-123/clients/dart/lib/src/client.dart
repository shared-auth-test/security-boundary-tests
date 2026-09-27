import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'errors.dart';
import 'models.dart';

/// A bounded, redirect-free HTTP client for the shared-auth API.
/// Loopback, private/link-local IPs, and in-cluster names — hosts a credential
/// may reach over cleartext because the traffic never leaves the trust boundary.
bool _internalHostAllowed(String host) {
  host = host.toLowerCase().replaceAll(RegExp(r'^\[|\]$'), '');
  if (host.isEmpty || host == 'localhost' || host.endsWith('.localhost'))
    return true;
  if (host == '::1') return true;
  for (final prefix in const <String>['fc', 'fd', 'fe8', 'fe9', 'fea', 'feb']) {
    if (host.startsWith(prefix)) return true;
  }
  final octets = host.split('.');
  if (octets.length == 4) {
    final parsed = octets.map(int.tryParse).toList();
    if (parsed.every((o) => o != null && o >= 0 && o <= 255)) {
      final a = parsed[0]!;
      final b = parsed[1]!;
      return a == 127 ||
          a == 10 ||
          (a == 172 && b >= 16 && b <= 31) ||
          (a == 192 && b == 168) ||
          (a == 169 && b == 254);
    }
  }
  return !host.contains('.') ||
      host.endsWith('.svc.cluster.local') ||
      host.endsWith('.internal');
}

/// Refuse to carry a credential over cleartext to a public host.
String _checkedBase(String baseUrl) {
  final parsed = Uri.tryParse(baseUrl);
  if (parsed != null &&
      parsed.scheme == 'http' &&
      !_internalHostAllowed(parsed.host)) {
    throw ArgumentError.value(
      baseUrl,
      'baseUrl',
      'shared-auth: refusing cleartext http:// to public host "${parsed.host}": '
          'use https://, an in-cluster address, or loopback',
    );
  }
  return _normalizeBaseUrl(baseUrl);
}

final class PasswordlessAccepted {
  const PasswordlessAccepted({required this.accepted});

  final bool accepted;

  factory PasswordlessAccepted.fromJson(JsonObject json) {
    final accepted = json['accepted'];
    if (accepted is! bool) {
      throw const FormatException('accepted must be a boolean');
    }
    return PasswordlessAccepted(accepted: accepted);
  }
}

final class SharedAuthClient {
  SharedAuthClient(
    String baseUrl, {
    http.Client? httpClient,
    Duration timeout = const Duration(seconds: 10),
    int maximumResponseBytes = 1024 * 1024,
    String? serviceCredential,
  })  : _baseUrl = _checkedBase(baseUrl),
        _http = httpClient ?? http.Client(),
        _ownsHttpClient = httpClient == null,
        _timeout = _positiveDuration(timeout),
        _maximumResponseBytes = _positiveMaximum(maximumResponseBytes),
        _serviceCredential = _nonEmpty(serviceCredential);

  final String _baseUrl;
  final http.Client _http;
  final bool _ownsHttpClient;
  final Duration _timeout;
  final int _maximumResponseBytes;
  String? _serviceCredential;

  /// Configure the service bearer used only for protected introspection.
  SharedAuthClient withServiceCredential(String credential) {
    _serviceCredential = _nonEmpty(credential);
    return this;
  }

  SharedAuthClient withoutServiceCredential() {
    _serviceCredential = null;
    return this;
  }

  void close() {
    if (_ownsHttpClient) {
      _http.close();
    }
  }

  Future<ExchangeResponse> exchange(String supabaseToken) =>
      _requestJson<ExchangeResponse>(
        'POST',
        '/auth/exchange',
        bearer: supabaseToken,
        decode: ExchangeResponse.fromJson,
      );

  Future<SessionResponse> register({
    required String email,
    required String password,
    String? displayName,
  }) =>
      _requestJson<SessionResponse>(
        'POST',
        '/auth/register',
        body: <String, Object?>{
          'email': email,
          'password': password,
          if (displayName != null) 'display_name': displayName,
        },
        decode: SessionResponse.fromJson,
      );

  Future<SessionResponse> login({
    required String email,
    required String password,
  }) =>
      _requestJson<SessionResponse>(
        'POST',
        '/auth/login',
        body: <String, Object?>{
          'email': email,
          'password': password,
        },
        decode: SessionResponse.fromJson,
      );

  Future<PasswordlessAccepted> requestPasswordless({
    required String email,
  }) =>
      _requestJson<PasswordlessAccepted>(
        'POST',
        '/auth/passwordless/request',
        body: <String, Object?>{'email': _passwordlessEmail(email)},
        decode: PasswordlessAccepted.fromJson,
      );

  Future<SessionResponse> consumePasswordless({
    required String email,
    required String otp,
  }) =>
      _requestJson<SessionResponse>(
        'POST',
        '/auth/passwordless/consume',
        body: <String, Object?>{
          'email': _passwordlessEmail(email),
          'otp': _emailOtp(otp),
        },
        decode: SessionResponse.fromJson,
      );

  Future<SessionResponse> refresh(String refreshToken) =>
      _requestJson<SessionResponse>(
        'POST',
        '/auth/refresh',
        body: <String, Object?>{'refresh_token': refreshToken},
        decode: SessionResponse.fromJson,
      );

  Future<void> logout(String refreshToken) async {
    const path = '/auth/logout';
    final response = await _request(
      'POST',
      path,
      body: <String, Object?>{'refresh_token': refreshToken},
    );
    _requireSuccess(path, response.statusCode);
  }

  Future<Introspection> introspect(
    String token, {
    String audience = 'oresoftware',
    List<String> requiredScopes = const <String>[],
  }) {
    const path = '/auth/introspect';
    final serviceCredential = _serviceCredential;
    if (serviceCredential == null) {
      throw const MissingServiceCredentialException();
    }
    final validatedToken = _introspectionToken(token);
    final validatedAudience = _introspectionValue(audience, 'audience');
    if (requiredScopes.length > 64) {
      throw ArgumentError.value(
        requiredScopes,
        'requiredScopes',
        'too many scopes',
      );
    }
    final validatedScopes = requiredScopes
        .map((scope) => _introspectionValue(scope, 'requiredScope'))
        .toList(growable: false);
    if (validatedScopes.toSet().length != validatedScopes.length) {
      throw ArgumentError.value(
        requiredScopes,
        'requiredScopes',
        'must not contain duplicates',
      );
    }
    return _requestJson<Introspection>(
      'POST',
      path,
      bearer: serviceCredential,
      body: <String, Object?>{
        'contract': 'IntrospectionRequest',
        'payload': <String, Object?>{
          'token': validatedToken,
          'audience': validatedAudience,
          'requiredScopes': validatedScopes,
        },
      },
      decode: Introspection.fromJson,
    );
  }

  Future<bool> verify(String token) async {
    const path = '/auth/verify';
    final response = await _request('GET', path, bearer: token);
    switch (response.statusCode) {
      case 200:
        return true;
      case 401:
        return false;
      default:
        throw SharedAuthStatusException(path, response.statusCode);
    }
  }

  Future<Jwks> jwks() => _requestJson<Jwks>(
        'GET',
        '/.well-known/jwks.json',
        decode: Jwks.fromJson,
      );

  Future<Capabilities> capabilities() => _requestJson<Capabilities>(
        'GET',
        '/auth/capabilities',
        decode: Capabilities.fromJson,
      );

  Future<List<Factor>> factors(String accessToken) async {
    const path = '/auth/factors';
    final json = await _requestJsonValue('GET', path, bearer: accessToken);
    if (json is! List<Object?>) {
      throw const SharedAuthDecodeException(
        path,
        FormatException('expected an array'),
      );
    }
    try {
      return List<Factor>.unmodifiable(
        json.map((Object? item) => Factor.fromJson(_asObject(item))),
      );
    } on SharedAuthClientException {
      rethrow;
    } on Object catch (error) {
      throw SharedAuthDecodeException(path, error);
    }
  }

  Future<TotpEnrollment> enrollTotp(String accessToken, {String? label}) =>
      _requestJson<TotpEnrollment>(
        'POST',
        '/auth/factors/totp/enroll',
        bearer: accessToken,
        body: <String, Object?>{
          if (label != null && label.trim().isNotEmpty) 'label': label.trim(),
        },
        decode: TotpEnrollment.fromJson,
      );

  Future<StepUpResponse> confirmTotp(
    String accessToken, {
    required String factorId,
    required String code,
  }) =>
      _requestJson<StepUpResponse>(
        'POST',
        '/auth/factors/totp/confirm',
        bearer: accessToken,
        body: <String, Object?>{'factor_id': factorId, 'code': code},
        decode: StepUpResponse.fromJson,
      );

  Future<void> deleteFactor(String accessToken, String factorId) async {
    final path = '/auth/factors/${Uri.encodeComponent(factorId)}';
    final response = await _request('DELETE', path, bearer: accessToken);
    _requireSuccess(path, response.statusCode);
  }

  Future<ChallengeStart> createChallenge(
    String accessToken,
    ChallengeKind kind,
  ) =>
      _requestJson<ChallengeStart>(
        'POST',
        '/auth/challenges',
        bearer: accessToken,
        body: <String, Object?>{'kind': kind.wireValue},
        decode: ChallengeStart.fromJson,
      );

  Future<StepUpResponse> verifyChallenge(
    String accessToken, {
    required String challengeId,
    required String code,
  }) {
    final path = '/auth/challenges/${Uri.encodeComponent(challengeId)}/verify';
    return _requestJson<StepUpResponse>(
      'POST',
      path,
      bearer: accessToken,
      body: <String, Object?>{'code': code},
      decode: StepUpResponse.fromJson,
    );
  }

  Future<CeremonyStart> startPasskeyRegistration(
    String accessToken, {
    String? label,
  }) =>
      _requestJson<CeremonyStart>(
        'POST',
        '/auth/passkeys/registration/options',
        bearer: accessToken,
        body: <String, Object?>{
          if (label != null && label.trim().isNotEmpty) 'label': label.trim(),
        },
        decode: CeremonyStart.fromJson,
      );

  Future<Factor> finishPasskeyRegistration(
    String accessToken, {
    required String challengeId,
    required Object credential,
    String? label,
  }) =>
      _requestJson<Factor>(
        'POST',
        '/auth/passkeys/registration/verify',
        bearer: accessToken,
        body: <String, Object?>{
          'challenge_id': challengeId,
          'credential': credential,
          if (label != null && label.trim().isNotEmpty) 'label': label.trim(),
        },
        decode: Factor.fromJson,
      );

  Future<CeremonyStart> startPasskeyAuthentication(String accessToken) =>
      _requestJson<CeremonyStart>(
        'POST',
        '/auth/passkeys/authentication/options',
        bearer: accessToken,
        body: const <String, Object?>{},
        decode: CeremonyStart.fromJson,
      );

  Future<StepUpResponse> finishPasskeyAuthentication(
    String accessToken, {
    required String challengeId,
    required Object credential,
  }) =>
      _requestJson<StepUpResponse>(
        'POST',
        '/auth/passkeys/authentication/verify',
        bearer: accessToken,
        body: <String, Object?>{
          'challenge_id': challengeId,
          'credential': credential,
        },
        decode: StepUpResponse.fromJson,
      );

  Future<Map<String, Object?>> oauthDiscovery() =>
      _requestJson<Map<String, Object?>>(
        'GET',
        '/.well-known/openid-configuration',
        decode: _asObject,
      );

  Future<Map<String, Object?>> authorizeDecision(
    String accessToken, {
    required String resource,
    required String action,
  }) =>
      _requestJson<Map<String, Object?>>(
        'POST',
        '/authz/decide',
        bearer: accessToken,
        body: <String, Object?>{'resource': resource, 'action': action},
        decode: _asObject,
      );

  Future<String> samlMetadata() async {
    const path = '/saml/metadata';
    final response = await _request('GET', path);
    _requireSuccess(path, response.statusCode);
    return response.body;
  }

  Future<Map<String, Object?>> samlSso(String idpEntityId) =>
      _requestJson<Map<String, Object?>>(
        'GET',
        '/saml/sso?idp_entity_id=${Uri.encodeQueryComponent(idpEntityId)}',
        decode: _asObject,
      );

  Future<Map<String, Object?>> samlAcs(
    String samlResponse, {
    String? relayState,
  }) =>
      _requestJson<Map<String, Object?>>(
        'POST',
        '/saml/acs',
        body: <String, Object?>{
          'SAMLResponse': samlResponse,
          if (relayState != null) 'RelayState': relayState,
        },
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimServiceProviderConfig() =>
      _requestJson<Map<String, Object?>>(
        'GET',
        '/scim/v2/ServiceProviderConfig',
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimListUsers(String accessToken) =>
      _requestJson<Map<String, Object?>>(
        'GET',
        '/scim/v2/Users',
        bearer: accessToken,
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimCreateUser(
    String accessToken,
    JsonObject user,
  ) =>
      _requestJson<Map<String, Object?>>(
        'POST',
        '/scim/v2/Users',
        bearer: accessToken,
        body: user,
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimGetUser(String accessToken, String id) =>
      _requestJson<Map<String, Object?>>(
        'GET',
        '/scim/v2/Users/${Uri.encodeComponent(id)}',
        bearer: accessToken,
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimReplaceUser(
    String accessToken,
    String id,
    JsonObject user,
  ) =>
      _requestJson<Map<String, Object?>>(
        'PUT',
        '/scim/v2/Users/${Uri.encodeComponent(id)}',
        bearer: accessToken,
        body: user,
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimPatchUser(
    String accessToken,
    String id,
    JsonObject patch,
  ) =>
      _requestJson<Map<String, Object?>>(
        'PATCH',
        '/scim/v2/Users/${Uri.encodeComponent(id)}',
        bearer: accessToken,
        body: patch,
        decode: _asObject,
      );

  Future<void> scimDeleteUser(String accessToken, String id) async {
    final path = '/scim/v2/Users/${Uri.encodeComponent(id)}';
    final response = await _request('DELETE', path, bearer: accessToken);
    _requireSuccess(path, response.statusCode);
  }

  Future<Map<String, Object?>> scimListGroups(String accessToken) =>
      _requestJson<Map<String, Object?>>(
        'GET',
        '/scim/v2/Groups',
        bearer: accessToken,
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimCreateGroup(
    String accessToken,
    JsonObject group,
  ) =>
      _requestJson<Map<String, Object?>>(
        'POST',
        '/scim/v2/Groups',
        bearer: accessToken,
        body: group,
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimGetGroup(String accessToken, String id) =>
      _requestJson<Map<String, Object?>>(
        'GET',
        '/scim/v2/Groups/${Uri.encodeComponent(id)}',
        bearer: accessToken,
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimReplaceGroup(
    String accessToken,
    String id,
    JsonObject group,
  ) =>
      _requestJson<Map<String, Object?>>(
        'PUT',
        '/scim/v2/Groups/${Uri.encodeComponent(id)}',
        bearer: accessToken,
        body: group,
        decode: _asObject,
      );

  Future<Map<String, Object?>> scimPatchGroup(
    String accessToken,
    String id,
    JsonObject patch,
  ) =>
      _requestJson<Map<String, Object?>>(
        'PATCH',
        '/scim/v2/Groups/${Uri.encodeComponent(id)}',
        bearer: accessToken,
        body: patch,
        decode: _asObject,
      );

  Future<void> scimDeleteGroup(String accessToken, String id) async {
    final path = '/scim/v2/Groups/${Uri.encodeComponent(id)}';
    final response = await _request('DELETE', path, bearer: accessToken);
    _requireSuccess(path, response.statusCode);
  }

  Future<T> _requestJson<T>(
    String method,
    String path, {
    String? bearer,
    JsonObject? body,
    required T Function(JsonObject json) decode,
  }) async {
    final value = await _requestJsonValue(
      method,
      path,
      bearer: bearer,
      body: body,
    );
    try {
      return decode(_asObject(value));
    } on SharedAuthClientException {
      rethrow;
    } on Object catch (error) {
      throw SharedAuthDecodeException(path, error);
    }
  }

  Future<Object?> _requestJsonValue(
    String method,
    String path, {
    String? bearer,
    JsonObject? body,
  }) async {
    final response = await _request(method, path, bearer: bearer, body: body);
    _requireSuccess(path, response.statusCode);
    try {
      return jsonDecode(response.body);
    } on Object catch (error) {
      throw SharedAuthDecodeException(path, error);
    }
  }

  Future<_WireResponse> _request(
    String method,
    String path, {
    String? bearer,
    JsonObject? body,
  }) async {
    final request = http.Request(method, Uri.parse('$_baseUrl$path'))
      ..followRedirects = false
      ..maxRedirects = 0
      ..headers['accept'] = 'application/json';

    final token = _nonEmpty(bearer);
    if (token != null) {
      request.headers['authorization'] = 'Bearer $token';
    }
    if (body != null) {
      request.headers['content-type'] = 'application/json';
      try {
        request.body = jsonEncode(body);
      } on Object catch (error) {
        throw ArgumentError.value(
          error,
          'body',
          'shared-auth request bodies must be JSON encodable',
        );
      }
    }

    try {
      return await (() async {
        final streamed = await _http.send(request);
        final responseBody = await _readBody(path, streamed.stream);
        return _WireResponse(streamed.statusCode, responseBody);
      })()
          .timeout(_timeout);
    } on SharedAuthClientException {
      rethrow;
    } on Object catch (error) {
      throw SharedAuthTransportException(path, error);
    }
  }

  Future<String> _readBody(String path, Stream<List<int>> stream) async {
    final bytes = BytesBuilder(copy: false);
    await for (final chunk in stream) {
      if (bytes.length + chunk.length > _maximumResponseBytes) {
        throw SharedAuthResponseTooLargeException(path, _maximumResponseBytes);
      }
      bytes.add(chunk);
    }
    try {
      return utf8.decode(bytes.takeBytes(), allowMalformed: false);
    } on Object catch (error) {
      throw SharedAuthDecodeException(path, error);
    }
  }

  static void _requireSuccess(String path, int statusCode) {
    if (statusCode == 401) {
      throw UnauthorizedException(path);
    }
    if (statusCode < 200 || statusCode >= 300) {
      throw SharedAuthStatusException(path, statusCode);
    }
  }
}

final class _WireResponse {
  const _WireResponse(this.statusCode, this.body);

  final int statusCode;
  final String body;
}

String _normalizeBaseUrl(String input) {
  final value = input.trim();
  final uri = Uri.tryParse(value);
  if (uri == null ||
      !uri.hasScheme ||
      (uri.scheme != 'http' && uri.scheme != 'https') ||
      uri.host.isEmpty ||
      uri.hasQuery ||
      uri.hasFragment ||
      uri.userInfo.isNotEmpty) {
    throw ArgumentError.value(input, 'baseUrl', 'expected an HTTP(S) base URL');
  }
  final normalizedPath = uri.path.replaceFirst(RegExp(r'/+$'), '');
  return uri.replace(path: normalizedPath).toString();
}

Duration _positiveDuration(Duration timeout) {
  if (timeout <= Duration.zero) {
    throw ArgumentError.value(timeout, 'timeout', 'must be positive');
  }
  return timeout;
}

int _positiveMaximum(int maximum) {
  if (maximum <= 0) {
    throw ArgumentError.value(
      maximum,
      'maximumResponseBytes',
      'must be positive',
    );
  }
  return maximum;
}

String? _nonEmpty(String? value) {
  final normalized = value?.trim();
  return normalized == null || normalized.isEmpty ? null : normalized;
}

String _passwordlessEmail(String value) {
  if (value.isEmpty ||
      value.length > 320 ||
      value != value.trim() ||
      value.contains(RegExp(r'[\x00-\x1F\x7F]')) ||
      !value.contains('@')) {
    throw ArgumentError.value(value, 'email', 'invalid email');
  }
  return value;
}

String _emailOtp(String value) {
  if (!RegExp(r'^[0-9]{6}$').hasMatch(value)) {
    throw ArgumentError.value('[REDACTED]', 'otp', 'must be exactly six ASCII digits');
  }
  return value;
}

String _introspectionToken(String value) {
  if (value.isEmpty ||
      value.length > 16 * 1024 ||
      value != value.trim() ||
      value.contains(RegExp(r'[\r\n]'))) {
    throw ArgumentError.value('[REDACTED]', 'token', 'invalid token');
  }
  return value;
}

String _introspectionValue(String value, String name) {
  if (value.isEmpty ||
      value.length > 128 ||
      !RegExp(r'^[A-Za-z0-9._:/-]+$').hasMatch(value)) {
    throw ArgumentError.value(value, name, 'invalid introspection value');
  }
  return value;
}

JsonObject _asObject(Object? value) {
  if (value is! Map<Object?, Object?>) {
    throw const FormatException('expected an object');
  }
  return value.map(
    (Object? key, Object? value) =>
        MapEntry<String, Object?>(key as String, value),
  );
}
