import 'package:common/model/file_type.dart';
import 'package:flutter/material.dart';
import 'package:localsend_app/util/native/channel/android_channel.dart' as android_channel;
import 'package:localsend_app/util/native/platform_check.dart';
import 'package:localsend_app/widget/dialogs/cannot_open_file_dialog.dart';
import 'package:open_filex/open_filex.dart';
import 'package:permission_handler/permission_handler.dart';

/// Extensions that the OS would *execute* (or treat as a launcher/shortcut)
/// rather than open with a viewer. Auto-opening a received file of one of these
/// types after a zero-interaction quickSave (H3) is a code-execution risk, so
/// the quickSave auto-open flow must skip them.
const executableExtensions = <String>{
  '.exe',
  '.bat',
  '.cmd',
  '.com',
  '.lnk',
  '.msi',
  '.ps1',
  '.scr',
  '.sh',
  '.command',
  '.app',
  '.jar',
  // Windows scripting / system entry-points that run on double-click.
  '.vbs',
  '.vbe',
  '.hta',
  '.wsf',
  '.wsh',
  '.cpl',
  '.reg',
  '.inf',
  // Linux launchers / portable apps.
  '.desktop',
  '.appimage',
};

/// Returns true if [filePath] has an executable/launcher extension.
bool isExecutableFile(String filePath) {
  final lower = filePath.toLowerCase();
  return executableExtensions.any((ext) => lower.endsWith(ext));
}

/// Opens the selected file which is stored on the device.
Future<void> openFile(
  BuildContext context,
  FileType fileType,
  String filePath, {
  void Function()? onDeleteTap,
}) async {
  if ((fileType == FileType.apk || filePath.toLowerCase().endsWith('.apk')) && checkPlatform([TargetPlatform.android])) {
    await Permission.requestInstallPackages.request();
  }

  if (filePath.startsWith('content://')) {
    await android_channel.openContentUri(uri: filePath);
    return;
  }

  final fileOpenResult = await OpenFilex.open(filePath);
  if (fileOpenResult.type != ResultType.done && context.mounted) {
    await CannotOpenFileDialog.open(context, filePath, onDeleteTap);
  }
}
