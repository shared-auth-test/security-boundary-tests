/// Base class for errors returned by the shared-auth client.
sealed class SharedAuthClientException implements Exception {
  const SharedAuthClientException(this.path);

  /// Endpoint path without the authority or credential-bearing values.
  final String path;
}

/// The shared-auth server returned its uniform 401 response.
final class UnauthorizedException extends SharedAuthClientException {
  const UnauthorizedException(super.path);

  @override
  String toString() => 'SharedAuthClientException: unauthorized at $path';
}

/// The server returned a non-success status other than 401.
final class SharedAuthStatusException extends SharedAuthClientException {
  const SharedAuthStatusException(super.path, this.statusCode);

  final int statusCode;

  @override
  String toString() =>
      'SharedAuthClientException: unexpected status $statusCode at $path';
}

/// The request failed at the transport layer or exceeded its deadline.
final class SharedAuthTransportException extends SharedAuthClientException {
  const SharedAuthTransportException(super.path, this.cause);

  final Object cause;

  @override
  String toString() => 'SharedAuthClientException: transport failure at $path';
}

/// A response exceeded the configured bounded body size.
final class SharedAuthResponseTooLargeException
    extends SharedAuthClientException {
  const SharedAuthResponseTooLargeException(super.path, this.maximumBytes);

  final int maximumBytes;

  @override
  String toString() =>
      'SharedAuthClientException: response exceeded $maximumBytes bytes at $path';
}

/// A successful response did not match the endpoint's JSON contract.
final class SharedAuthDecodeException extends SharedAuthClientException {
  const SharedAuthDecodeException(super.path, this.cause);

  final Object cause;

  @override
  String toString() =>
      'SharedAuthClientException: invalid response contract at $path';
}

/// Protected introspection was called without its service credential.
final class MissingServiceCredentialException
    extends SharedAuthClientException {
  const MissingServiceCredentialException() : super('/auth/introspect');

  @override
  String toString() =>
      'SharedAuthClientException: introspection service credential is required';
}
