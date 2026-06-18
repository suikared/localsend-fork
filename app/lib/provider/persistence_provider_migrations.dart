part of 'persistence_provider.dart';

const _latestVersion = 3;

Future<void> _runMigrations(int from) async {
  switch (from) {
    case 1:
      await _migrate2();
      await _migrate3();
      await SharedPreferencesStorePlatform.instance.setValue('Int', 'flutter.$_version', _latestVersion);
      break;
    case 2:
      await _migrate3();
      await SharedPreferencesStorePlatform.instance.setValue('Int', 'flutter.$_version', _latestVersion);
      break;
  }
}

Future<void> _migrate2() async {
  _logger.info('Migrating to version 2');
  if (SharedPreferencesStorePlatform.instance is! SharedPreferencesPortable) {
    await enableContextMenu();

    if (defaultTargetPlatform == TargetPlatform.windows) {
      final newFolder = File(_windowsFile).parent;
      if (!newFolder.existsSync()) {
        newFolder.createSync(recursive: true);
      }

      final legacyFile = File(_windowsLegacyFile);
      legacyFile.copySync(_windowsFile);
      try {
        legacyFile.parent.parent.deleteSync(recursive: true);
      } catch (e) {
        _logger.warning('Failed to delete legacy folder: $e');
      }
      SharedPreferencesStorePlatform.instance = SharedPreferencesFile(filePath: _windowsFile);
    }
  }
}

/// Migrates a legacy plaintext receive PIN (pre-fix storage) to a salted
/// PBKDF2 record so the plaintext no longer sits in SharedPreferences.
Future<void> _migrate3() async {
  _logger.info('Migrating to version 3 (hash receive PIN)');
  final store = SharedPreferencesStorePlatform.instance;
  final key = 'flutter.$_receivePin';
  final raw = (await store.getAll())[key] as String?;
  if (raw == null) return; // no PIN set
  if (PinHashRecord.tryDecode(raw) != null) return; // already a record
  // Legacy plaintext (or any unrecognized shape): hash and replace.
  final record = hashPin(raw).encode();
  await store.setValue('String', key, record);
}
