import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_auth_client/shared_auth_client.dart';
import 'package:test/test.dart';

void main() {
  group('passwordless auth', () {
    test('request preserves enumeration-resistant accepted response', () async {
      final transport = MockClient((request) async {
        expect(request.method, 'POST');
        expect(
          request.url.path,
          '/shared-auth/auth/passwordless/request',
        );
        expect(
          jsonDecode(request.body),
          <String, Object?>{'email': 'person@example.invalid'},
        );
        return http.Response(jsonEncode(<String, Object?>{'accepted': true}), 202);
      });
      final client = SharedAuthClient(
        'https://gateway.example/shared-auth',
        httpClient: transport,
      );

      final response = await client.requestPasswordless(
        email: 'person@example.invalid',
      );

      expect(response.accepted, isTrue);
    });

    test('consume sends only email and a strict six-digit code', () async {
      final validCode = List<String>.filled(6, '0').join();
      final transport = MockClient((request) async {
        expect(request.method, 'POST');
        expect(
          request.url.path,
          '/shared-auth/auth/passwordless/consume',
        );
        expect(
          jsonDecode(request.body),
          <String, Object?>{
            'email': 'person@example.invalid',
            'otp': validCode,
          },
        );
        return http.Response(
          jsonEncode(<String, Object?>{
            'access_token': 'fixture-access',
            'token_type': 'Bearer',
            'expires_at': 42,
            'refresh_token': 'fixture-refresh',
            'refresh_expires_at': 84,
            'shared_user_id': 'fixture-user',
            'provider': 'magic_link',
            'roles': <String>[],
            'amr': <String>['email'],
          }),
          200,
        );
      });
      final client = SharedAuthClient(
        'https://gateway.example/shared-auth',
        httpClient: transport,
      );

      final session = await client.consumePasswordless(
        email: 'person@example.invalid',
        otp: validCode,
      );

      expect(session.provider, 'magic_link');
      expect(session.amr, <String>['email']);
    });

    test('malformed codes fail before transport and redact the value', () async {
      var transportUsed = false;
      final transport = MockClient((request) async {
        transportUsed = true;
        return http.Response('{}', 500);
      });
      final client = SharedAuthClient(
        'https://gateway.example/shared-auth',
        httpClient: transport,
      );

      for (final invalidCode in <String>['', '12345', '1234567', '12a456']) {
        expect(
          () => client.consumePasswordless(
            email: 'person@example.invalid',
            otp: invalidCode,
          ),
          throwsA(
            isA<ArgumentError>().having(
              (error) => error.invalidValue,
              'invalidValue',
              '[REDACTED]',
            ),
          ),
        );
      }
      expect(transportUsed, isFalse);
    });

    test('malformed email fails before transport', () async {
      var transportUsed = false;
      final transport = MockClient((request) async {
        transportUsed = true;
        return http.Response('{}', 500);
      });
      final client = SharedAuthClient(
        'https://gateway.example/shared-auth',
        httpClient: transport,
      );

      expect(
        () => client.requestPasswordless(email: ' person@example.invalid'),
        throwsArgumentError,
      );
      expect(transportUsed, isFalse);
    });
  });
}
