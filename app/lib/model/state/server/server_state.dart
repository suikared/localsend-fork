import 'package:dart_mappable/dart_mappable.dart';
import 'package:localsend_app/model/state/send/web/web_send_state.dart';
import 'package:localsend_app/model/state/server/receive_session_state.dart';
import 'package:localsend_app/util/simple_server.dart';

part 'server_state.mapper.dart';

@MappableClass()
class ServerState with ServerStateMappable {
  final SimpleServer httpServer;
  final String alias;
  final int port;
  final bool https;
  final ReceiveSessionState? session;
  final WebSendState? webSendState;
  final Map<String, int> pinAttempts; // IP address -> attempts (reset on success / after pinCooldown)
  final Map<String, DateTime> pinLockedAt; // IP address -> when the lockout started

  const ServerState({
    required this.httpServer,
    required this.alias,
    required this.port,
    required this.https,
    required this.session,
    required this.webSendState,
    required this.pinAttempts,
    required this.pinLockedAt,
  });

  @override
  String toString() {
    return 'ServerState(alias: $alias, port: $port, https: $https, session: $session, webSendState: $webSendState, pinAttempts: $pinAttempts, pinLockedAt: $pinLockedAt)';
  }
}
