import 'dart:io';

import 'package:localsend_app/util/native/file_saver.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

/// Negative security tests for the path-traversal guard in
/// `digestFilePathAndPrepareDirectory`. These must fail if the guard regresses
/// (e.g. if a `length > 1` shortcut is reintroduced that skips single-segment
/// `..` file names).
void main() {
  late Directory parent;

  setUp(() async {
    parent = await Directory.systemTemp.createTemp('ls_traversal_');
  });

  tearDown(() async {
    if (parent.existsSync()) {
      await parent.delete(recursive: true);
    }
  });

  for (final malicious in <String>[
    '..',
    '../evil.txt',
    'a/../..',
    'a/../../evil.txt',
    'sub/../../evil.txt',
    './../evil.txt',
  ]) {
    test('rejects path traversal: $malicious', () async {
      // Arrange + Act + Assert
      await expectLater(
        digestFilePathAndPrepareDirectory(
          parentDirectory: parent.path,
          fileName: malicious,
          createdDirectories: {},
        ),
        throwsA(anything),
      );

      // Nothing outside the parent may have been created.
      expect(p.isWithin(parent.path, p.join(parent.path, malicious)), isFalse);
    });
  }

  test('rejects an absolute path (drive / root) injection', () async {
    // Arrange — absolute path must be platform-appropriate so the test is
    // meaningful on both Windows and Unix CI.
    final absolute = Platform.isWindows ? r'C:\Windows\evil' : '/etc/evil';

    // Act + Assert: the guard must reject before anything is written.
    await expectLater(
      digestFilePathAndPrepareDirectory(
        parentDirectory: parent.path,
        fileName: absolute,
        createdDirectories: {},
      ),
      throwsA(anything),
    );

    // An absolute path is by definition not within the parent.
    expect(p.isWithin(parent.path, absolute), isFalse);
  });

  test('accepts a simple file name within parent', () async {
    // Arrange + Act
    final (destPath, _, baseName) = await digestFilePathAndPrepareDirectory(
      parentDirectory: parent.path,
      fileName: 'photo.jpg',
      createdDirectories: {},
    );

    // Assert
    expect(p.isWithin(parent.path, destPath), isTrue);
    expect(baseName, 'photo.jpg');
  });

  test('accepts a nested file name within parent', () async {
    // Arrange + Act
    final (destPath, _, baseName) = await digestFilePathAndPrepareDirectory(
      parentDirectory: parent.path,
      fileName: 'sub/photo.jpg',
      createdDirectories: {},
    );

    // Assert
    expect(p.isWithin(parent.path, destPath), isTrue);
    expect(baseName, 'photo.jpg');
  });
}
