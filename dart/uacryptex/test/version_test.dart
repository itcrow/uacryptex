import 'package:test/test.dart';
import 'package:uacryptex/uacryptex.dart';

void main() {
  test('libraryVersion returns non-empty string when native lib is present', () {
    try {
      final v = libraryVersion();
      expect(v, isNotEmpty);
    } on StateError catch (e) {
      // Native library not built in CI / dev environment.
      expect(e.message, contains('native library not found'));
    }
  });
}
