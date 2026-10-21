typedef JsonObject = Map<String, Object?>;

final class ExchangeResponse {
  const ExchangeResponse({
    required this.accessToken,
    required this.tokenType,
    required this.expiresAt,
    required this.sharedUserId,
    this.authTime,
    this.refreshToken,
    this.refreshExpiresAt,
    this.project,
    this.provider,
    this.providerTenant,
    this.providerSubject,
    this.roles = const <String>[],
    this.amr = const <String>[],
    this.acr,
  });

  final String accessToken;
  final String tokenType;
  final int expiresAt;
  final String sharedUserId;
  final int? authTime;
  final String? refreshToken;
  final int? refreshExpiresAt;
  final String? project;
  final String? provider;
  final String? providerTenant;
  final String? providerSubject;
  final List<String> roles;
  final List<String> amr;
  final String? acr;

  factory ExchangeResponse.fromJson(JsonObject json) => ExchangeResponse(
        accessToken: _requiredString(json, 'access_token'),
        tokenType: _requiredString(json, 'token_type'),
        expiresAt: _requiredInt(json, 'expires_at'),
        sharedUserId: _requiredString(json, 'shared_user_id'),
        authTime: _optionalInt(json, 'auth_time'),
        refreshToken: _optionalString(json, 'refresh_token'),
        refreshExpiresAt: _optionalInt(json, 'refresh_expires_at'),
        project: _optionalString(json, 'project'),
        provider: _optionalString(json, 'provider'),
        providerTenant: _optionalString(json, 'provider_tenant'),
        providerSubject: _optionalString(json, 'provider_subject'),
        roles: _stringList(json, 'roles'),
        amr: _stringList(json, 'amr'),
        acr: _optionalString(json, 'acr'),
      );
}

final class SessionResponse {
  const SessionResponse({
    required this.accessToken,
    required this.tokenType,
    required this.expiresAt,
    required this.refreshToken,
    required this.refreshExpiresAt,
    required this.sharedUserId,
    required this.provider,
    required this.roles,
    required this.amr,
    this.acr,
  });

  final String accessToken;
  final String tokenType;
  final int expiresAt;
  final String refreshToken;
  final int refreshExpiresAt;
  final String sharedUserId;
  final String provider;
  final List<String> roles;
  final List<String> amr;
  final String? acr;

  factory SessionResponse.fromJson(JsonObject json) => SessionResponse(
        accessToken: _requiredString(json, 'access_token'),
        tokenType: _requiredString(json, 'token_type'),
        expiresAt: _requiredInt(json, 'expires_at'),
        refreshToken: _requiredString(json, 'refresh_token'),
        refreshExpiresAt: _requiredInt(json, 'refresh_expires_at'),
        sharedUserId: _requiredString(json, 'shared_user_id'),
        provider: _requiredString(json, 'provider'),
        roles: _requiredStringList(json, 'roles'),
        amr: _requiredStringList(json, 'amr'),
        acr: _optionalString(json, 'acr'),
      );
}

final class StepUpResponse {
  const StepUpResponse({
    required this.accessToken,
    required this.tokenType,
    required this.expiresAt,
    required this.amr,
    this.acr,
  });

  final String accessToken;
  final String tokenType;
  final int expiresAt;
  final List<String> amr;
  final String? acr;

  factory StepUpResponse.fromJson(JsonObject json) => StepUpResponse(
        accessToken: _requiredString(json, 'access_token'),
        tokenType: _requiredString(json, 'token_type'),
        expiresAt: _requiredInt(json, 'expires_at'),
        amr: _stringList(json, 'amr'),
        acr: _optionalString(json, 'acr'),
      );
}

final class Introspection {
  Introspection({
    required this.active,
    this.sub,
    this.sid,
    this.project,
    this.provider,
    this.providerTenant,
    this.providerSubject,
    this.email,
    this.emailVerified,
    this.roles = const <String>[],
    this.amr = const <String>[],
    this.acr,
    this.exp,
    JsonObject claims = const <String, Object?>{},
  }) : claims = Map<String, Object?>.unmodifiable(claims);

  final bool active;
  final String? sub;
  final String? sid;
  final String? project;
  final String? provider;
  final String? providerTenant;
  final String? providerSubject;
  final String? email;
  final bool? emailVerified;
  final List<String> roles;
  final List<String> amr;
  final String? acr;
  final int? exp;

  /// The complete object, including extension claims unknown to this SDK.
  final JsonObject claims;

  /// Missing or inactive assurance claims never satisfy an explicit policy.
  bool hasAssurance(String requiredAcr) => active && acr == requiredAcr;

  bool usedMethod(String method) => active && amr.contains(method);

  bool hasRole(String role) => active && roles.contains(role);

  factory Introspection.fromJson(JsonObject json) => Introspection(
        active: _requiredBool(json, 'active'),
        sub: _optionalString(json, 'sub'),
        sid: _optionalString(json, 'sid'),
        project: _optionalString(json, 'project'),
        provider: _optionalString(json, 'provider'),
        providerTenant: _optionalString(json, 'provider_tenant'),
        providerSubject: _optionalString(json, 'provider_subject'),
        email: _optionalString(json, 'email'),
        emailVerified: _optionalBool(json, 'email_verified'),
        roles: _stringList(json, 'roles'),
        amr: _stringList(json, 'amr'),
        acr: _optionalString(json, 'acr'),
        exp: _optionalInt(json, 'exp'),
        claims: json,
      );
}

final class Jwks {
  const Jwks({required this.keys});

  final List<JsonObject> keys;

  factory Jwks.fromJson(JsonObject json) {
    final value = json['keys'];
    if (value is! List<Object?>) {
      throw const FormatException('keys must be an array');
    }
    return Jwks(
      keys: List<JsonObject>.unmodifiable(
        value.map((Object? key) {
          if (key is! Map<Object?, Object?>) {
            throw const FormatException('each key must be an object');
          }
          return Map<String, Object?>.unmodifiable(
            key.map(
              (Object? name, Object? value) =>
                  MapEntry<String, Object?>(name as String, value),
            ),
          );
        }),
      ),
    );
  }
}

final class Capabilities {
  const Capabilities({
    required this.mfaEnabled,
    required this.methods,
    this.threefaImportScheme,
    this.biometricModel,
  });

  final bool mfaEnabled;
  final List<String> methods;
  final String? threefaImportScheme;
  final String? biometricModel;

  factory Capabilities.fromJson(JsonObject json) => Capabilities(
        mfaEnabled: _requiredBool(json, 'mfa_enabled'),
        methods: _stringList(json, 'methods'),
        threefaImportScheme: _optionalString(json, 'threefa_import_scheme'),
        biometricModel: _optionalString(json, 'biometric_model'),
      );
}

final class Factor {
  const Factor({
    required this.factorId,
    required this.kind,
    required this.enabled,
    required this.createdAt,
    this.label,
    this.confirmedAt,
    this.lastUsedAt,
  });

  final String factorId;
  final String kind;
  final String? label;
  final bool enabled;
  final String? confirmedAt;
  final String? lastUsedAt;
  final String createdAt;

  factory Factor.fromJson(JsonObject json) => Factor(
        factorId: _requiredString(json, 'factor_id'),
        kind: _requiredString(json, 'kind'),
        label: _optionalString(json, 'label'),
        enabled: _requiredBool(json, 'enabled'),
        confirmedAt: _optionalString(json, 'confirmed_at'),
        lastUsedAt: _optionalString(json, 'last_used_at'),
        createdAt: _requiredString(json, 'created_at'),
      );
}

final class TotpEnrollment {
  const TotpEnrollment({
    required this.factorId,
    required this.secretBase32,
    required this.otpauthUri,
    required this.threefaImportUri,
  });

  final String factorId;
  final String secretBase32;
  final String otpauthUri;
  final String threefaImportUri;

  factory TotpEnrollment.fromJson(JsonObject json) => TotpEnrollment(
        factorId: _requiredString(json, 'factor_id'),
        secretBase32: _requiredString(json, 'secret_base32'),
        otpauthUri: _requiredString(json, 'otpauth_uri'),
        threefaImportUri: _requiredString(json, 'threefa_import_uri'),
      );
}

enum ChallengeKind {
  emailOtp('email_otp'),
  smsOtp('sms_otp');

  const ChallengeKind(this.wireValue);

  final String wireValue;
}

final class ChallengeStart {
  const ChallengeStart({
    required this.challengeId,
    required this.expiresAt,
    required this.delivery,
  });

  final String challengeId;
  final String expiresAt;
  final String delivery;

  factory ChallengeStart.fromJson(JsonObject json) => ChallengeStart(
        challengeId: _requiredString(json, 'challenge_id'),
        expiresAt: _requiredString(json, 'expires_at'),
        delivery: _requiredString(json, 'delivery'),
      );
}

final class CeremonyStart {
  const CeremonyStart({
    required this.challengeId,
    required this.options,
    required this.expiresAt,
  });

  final String challengeId;
  final Object? options;
  final String expiresAt;

  factory CeremonyStart.fromJson(JsonObject json) {
    if (!json.containsKey('options')) {
      throw const FormatException('missing options');
    }
    return CeremonyStart(
      challengeId: _requiredString(json, 'challenge_id'),
      options: json['options'],
      expiresAt: _requiredString(json, 'expires_at'),
    );
  }
}

String _requiredString(JsonObject json, String key) {
  final value = json[key];
  if (value is! String) {
    throw FormatException('$key must be a string');
  }
  return value;
}

String? _optionalString(JsonObject json, String key) {
  final value = json[key];
  if (value == null) {
    return null;
  }
  if (value is! String) {
    throw FormatException('$key must be a string or null');
  }
  return value;
}

int _requiredInt(JsonObject json, String key) {
  final value = json[key];
  if (value is! int) {
    throw FormatException('$key must be an integer');
  }
  return value;
}

int? _optionalInt(JsonObject json, String key) {
  final value = json[key];
  if (value == null) {
    return null;
  }
  if (value is! int) {
    throw FormatException('$key must be an integer or null');
  }
  return value;
}

bool _requiredBool(JsonObject json, String key) {
  final value = json[key];
  if (value is! bool) {
    throw FormatException('$key must be a boolean');
  }
  return value;
}

bool? _optionalBool(JsonObject json, String key) {
  final value = json[key];
  if (value == null) {
    return null;
  }
  if (value is! bool) {
    throw FormatException('$key must be a boolean or null');
  }
  return value;
}

List<String> _stringList(JsonObject json, String key) {
  final value = json[key];
  if (value == null) {
    return const <String>[];
  }
  if (value is! List<Object?> || value.any((Object? item) => item is! String)) {
    throw FormatException('$key must be an array of strings');
  }
  return List<String>.unmodifiable(value.cast<String>());
}

List<String> _requiredStringList(JsonObject json, String key) {
  if (!json.containsKey(key)) {
    throw FormatException('missing $key');
  }
  return _stringList(json, key);
}
