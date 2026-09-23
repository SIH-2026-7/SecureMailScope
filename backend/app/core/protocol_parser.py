from enum import Enum
from .tls_parser import records, parse_handshake
from ..models.schemas import SessionRecord


class State(str, Enum):
    CONNECTED = 'CONNECTED'
    GREETING = 'GREETING'
    EHLO_SENT = 'EHLO_SENT'
    CAPABILITIES_RECEIVED = 'CAPABILITIES_RECEIVED'
    STARTTLS_SENT = 'STARTTLS_SENT'
    TLS_HANDSHAKE = 'TLS_HANDSHAKE'
    TLS_ESTABLISHED = 'TLS_ESTABLISHED'
    AUTH_SENT = 'AUTH_SENT'
    AUTH_COMPLETE = 'AUTH_COMPLETE'
    MAIL_FROM = 'MAIL_FROM'
    RCPT_TO = 'RCPT_TO'
    DATA = 'DATA'
    SELECT = 'SELECT'
    FETCH = 'FETCH'
    USER = 'USER'
    TRANSACTION = 'TRANSACTION'
    QUIT = 'QUIT'


TRANSITIONS = {
    'SMTP': {'EHLO': State.EHLO_SENT, 'HELO': State.EHLO_SENT, 'STARTTLS': State.STARTTLS_SENT,
             'AUTH': State.AUTH_SENT, 'MAIL': State.MAIL_FROM, 'RCPT': State.RCPT_TO,
             'DATA': State.DATA, 'QUIT': State.QUIT},
    'IMAP': {'STARTTLS': State.STARTTLS_SENT, 'LOGIN': State.AUTH_SENT, 'AUTHENTICATE': State.AUTH_SENT,
             'SELECT': State.SELECT, 'FETCH': State.FETCH, 'SEARCH': State.FETCH, 'LOGOUT': State.QUIT},
    'POP3': {'STLS': State.STARTTLS_SENT, 'USER': State.USER, 'PASS': State.AUTH_SENT,
             'AUTH': State.AUTH_SENT, 'STAT': State.TRANSACTION, 'LIST': State.TRANSACTION,
             'RETR': State.TRANSACTION, 'QUIT': State.QUIT},
}


def parse(stream):
    first = stream['rows'][0]
    def evidence(p):
        return dict(frame_no=p['frame'], timestamp=p['ts'], stream_id=stream['id'])
    s = SessionRecord(session_id=stream['id'], protocol=stream['protocol'], client_ip=stream['client'][0],
                      server_ip=stream['server'][0], server_port=stream['server'][1],
                      evidence=evidence(first), warnings=stream['warnings'].copy())
    events = []
    for direction, chunks in stream['directions'].items():
        logical_ts = 0
        for index, (kind, body, p) in enumerate(records(chunks)):
            logical_ts = max(logical_ts, p['ts'])
            events.append((logical_ts, index, p['frame'], direction, kind, body, p))
    events.sort(key=lambda item: item[:3])
    state, encrypted, auth_exchange, body_mode = State.CONNECTED, False, False, False
    handshake_buffers = {'client': b'', 'server': b''}
    certs, cert_evidence = [], None
    saw_server, saw_client, tls_requested_at = False, False, None
    for _, _, _, direction, kind, body, p in events:
        ev = evidence(p)
        if kind == 'incomplete':
            s.warnings.append(f'Incomplete record or command at frame {p["frame"]}.')
            continue
        if kind == 'invalid':
            s.warnings.append(f'Invalid TLS record at frame {p["frame"]}.')
            continue
        if isinstance(kind, int):
            if kind == 20:
                # TLS <=1.2 encrypted handshake follows ChangeCipherSpec.
                encrypted = True
                s.tls['change_cipher_spec_observed'] = True
            if kind == 23:
                if s.tls.get('server_hello'):
                    state = State.TLS_ESTABLISHED
                    encrypted = True
                    s.tls['encrypted_records_observed'] = True
                continue
            if kind != 22 or encrypted:
                continue
            state = State.TLS_HANDSHAKE
            if s.starttls_requested:
                s.starttls_used = True
            pending = handshake_buffers[direction] + body
            while len(pending) >= 4:
                length = int.from_bytes(pending[1:4], 'big')
                if length > 4_000_000:
                    s.warnings.append('Oversized TLS handshake skipped.')
                    pending = b''
                    break
                if len(pending) < length + 4:
                    break
                msg_type, message = pending[0], pending[4:4 + length]
                pending = pending[4 + length:]
                try:
                    parse_handshake(msg_type, message, s.tls)
                    label = {1: 'ClientHello', 2: 'ServerHello', 11: 'Certificate'}.get(msg_type, f'Handshake {msg_type}')
                    s.commands.append({**ev, 'direction': direction, 'line': label, 'state': state.value})
                    s.tls[f'{label}_evidence'] = ev
                    if msg_type == 11 and s.tls.get('version') != 'TLS1.3':
                        offset = 3
                        while offset + 3 <= len(message):
                            size = int.from_bytes(message[offset:offset + 3], 'big')
                            offset += 3
                            if size == 0 or offset + size > len(message):
                                raise ValueError('Invalid certificate length')
                            certs.append(message[offset:offset + size])
                            offset += size
                        cert_evidence = ev
                except (ValueError, IndexError, __import__('struct').error):
                    s.warnings.append(f'Partial or malformed TLS handshake at frame {p["frame"]}.')
            handshake_buffers[direction] = pending
            continue
        if encrypted:
            continue
        # Never retain arbitrary content, SASL continuations, mailbox data, or message bodies.
        line = body.decode('utf-8', errors='replace').strip()
        words = line.split()
        if not words:
            continue
        if direction == 'client':
            saw_client = True
            command = words[1].upper() if s.protocol == 'IMAP' and len(words) > 1 else words[0].upper()
            if body_mode:
                if line == '.':
                    body_mode = False
                continue
            if auth_exchange and command not in TRANSITIONS.get(s.protocol, {}):
                continue
            new_state = TRANSITIONS.get(s.protocol, {}).get(command)
            if not new_state:
                continue
            if tls_requested_at is not None and command not in ('STARTTLS', 'STLS', 'QUIT', 'LOGOUT'):
                s.plaintext_after_starttls = True
                s.tls['plaintext_after_starttls_evidence'] = ev
            if command in ('AUTH', 'AUTHENTICATE', 'LOGIN', 'PASS'):
                s.auth_before_tls = True
                s.tls['auth_evidence'] = ev
                auth_exchange = True
            if command in ('STARTTLS', 'STLS'):
                s.starttls_requested = True
                tls_requested_at = p['frame']
                s.tls['starttls_evidence'] = ev
            if command == 'DATA':
                body_mode = True
            state = new_state
            safe_line = command + (' [REDACTED]' if len(words) > (2 if s.protocol == 'IMAP' else 1) else '')
        else:
            saw_server = True
            upper = line.upper()
            if 'STARTTLS' in upper or (s.protocol == 'POP3' and upper == 'STLS'):
                s.starttls_advertised = True
                s.tls['capability_evidence'] = ev
            code = words[0][:3] if words[0][:3].isdigit() else ('+OK' if upper.startswith('+OK') else '-ERR' if upper.startswith('-ERR') else '*')
            safe_line = code + (' STARTTLS advertised' if 'STARTTLS' in upper or upper == 'STLS' else ' [response content omitted]')
            if state == State.CONNECTED:
                state = State.GREETING
            elif state == State.EHLO_SENT and code.startswith('250'):
                state = State.CAPABILITIES_RECEIVED
            elif state == State.AUTH_SENT and (code.startswith('235') or code == '+OK' or ' OK ' in upper):
                state = State.AUTH_COMPLETE
                auth_exchange = False
        s.commands.append({**ev, 'direction': direction, 'line': safe_line, 'state': state.value})
    if any(handshake_buffers.values()):
        s.warnings.append('Incomplete TLS handshake message.')
    tls_complete = s.tls.get('server_hello') and (s.tls.get('encrypted_records_observed') or s.tls.get('change_cipher_spec_observed'))
    s.complete = bool(stream['has_syn'] and (tls_complete if s.tls.get('server_hello') else saw_server and saw_client) and not any('gap' in w or 'malformed' in w or 'Incomplete' in w for w in s.warnings))
    if not s.complete:
        s.warnings.append('Partial session; posture score is unavailable.')
    if s.tls.get('version') == 'TLS1.3':
        s.warnings.append('TLS 1.3 certificate and authentication messages are encrypted; not observable without session secrets.')
    return s, certs, cert_evidence
