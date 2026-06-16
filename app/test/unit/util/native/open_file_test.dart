import 'package:localsend_app/util/native/open_file.dart';
import 'package:test/test.dart';

void main() {
  group('isExecutableFile', () {
    for (final exe in <String>[
      'photo.exe',
      'a/b/c.BAT',
      'run.CMD',
      'shortcut.lnk',
      'script.sh',
      'app.jar',
      'malware.vbs',
      'evil.hta',
      'import.reg',
      'launch.desktop',
    ]) {
      test('flags executable: $exe', () {
        expect(isExecutableFile(exe), isTrue);
      });
    }

    for (final safe in <String>['photo.jpg', 'doc.pdf', 'video.mp4', 'image.PNG', 'noext', 'readme.txt']) {
      test('does not flag safe: $safe', () {
        expect(isExecutableFile(safe), isFalse);
      });
    }

    test('extension-name deception is still flagged', () {
      // A file literally named "report.pdf.exe" must be treated as executable.
      expect(isExecutableFile('report.pdf.exe'), isTrue);
    });
  });
}
