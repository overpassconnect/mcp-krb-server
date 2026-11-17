"""Unified injectable fake of python-gssapi for hermetic tests - covers BOTH the
initiator role (the client bridge) and the acceptor role (server).

Inject before importing the code under test:
    import sys, types, fake_gssapi
    sys.modules['gssapi'] = fake_gssapi
    _e = types.ModuleType('gssapi.exceptions'); _e.GSSError = fake_gssapi.GSSError
    sys.modules['gssapi.exceptions'] = _e

Acceptor token convention (server tests craft these as base64):
    b'GOOD:<principal>'  -> complete, initiator = <principal>, mech = krb5(SPNEGO)
    b'BADMECH:<princ>'   -> complete but a non-krb5 mech (tests the mech pin)
    b'INCOMPLETE'        -> NOT complete (tests the [C1] completeness gate)
    anything else        -> raises GSSError (defective token)
Initiator step() returns a deterministic token and records the context, so client
tests can assert the service name / flags / mech / fresh-per-call. The token has
the shape the real library gives for the mech asked for: a krb5
InitialContextToken for krb5 (or no mech), and for SPNEGO a NegTokenInit whose
mech list is built from WORKSTATION_MECHS, the credentials the user holds. Add
_NTLM there to model a Mac after Finder mounted an SMB share.
"""
contexts = []   # initiator contexts (client bridge tests)


class GSSError(Exception):
    pass


class OID:
    def __init__(self, seq):
        self.seq = seq

    @staticmethod
    def from_int_seq(seq):
        return OID(seq)

    @property
    def dotted_form(self):
        # Real python-gssapi exposes this, and delegation.py derives the DER
        # encoding of a mech OID from it rather than hardcoding byte strings.
        # The fake is only useful while it matches the API it stands in for.
        return self.seq

    def __eq__(self, o):
        return isinstance(o, OID) and o.seq == self.seq

    def __hash__(self):
        return hash(self.seq)


_KRB5 = '1.2.840.113554.1.2.2'
_SPNEGO = '1.3.6.1.5.5.2'
_NTLM = '1.3.6.1.4.1.311.2.2.10'

# The credentials the user holds, by mech. SPNEGO offers every one of them, krb5
# first, which is what GSS.framework did on a Mac holding a ticket and the NTLM
# credentials an SMB mount leaves behind (measured 2026-11-17).
WORKSTATION_MECHS = [_KRB5]

_OID_DER = {
    _KRB5: bytes.fromhex('06092a864886f712010202'),
    _SPNEGO: bytes.fromhex('06062b0601050502'),
    _NTLM: bytes.fromhex('060a2b06010401823702020a'),
}


def _der(tag, payload):
    n = len(payload)
    if n < 0x80:
        length = bytes((n,))
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        length = bytes((0x80 | len(b),)) + b
    return bytes((tag,)) + length + payload


def _krb5_token(ap_req):
    """RFC 4121 section 4.1: [APPLICATION 0] { krb5 OID, TOK_ID 01 00, AP-REQ }."""
    return _der(0x60, _OID_DER[_KRB5] + b'\x01\x00' + ap_req)


def _spnego_token(ap_req):
    """A NegTokenInit offering every mech the workstation holds, with the krb5
    token as the optimistic mechToken."""
    mech_types = _der(0xA0, _der(0x30, b''.join(_OID_DER[m] for m in WORKSTATION_MECHS)))
    mech_token = _der(0xA2, _der(0x04, _krb5_token(ap_req)))
    return _der(0x60, _OID_DER[_SPNEGO] + _der(0xA0, _der(0x30, mech_types + mech_token)))


class _NameType:
    hostbased_service = 'hostbased_service'
    kerberos_principal = 'kerberos_principal'


NameType = _NameType()


class RequirementFlag:
    mutual_authentication = 'mutual_authentication'
    out_of_sequence_detection = 'out_of_sequence_detection'
    delegate_to_peer = 'delegate_to_peer'
    integrity = 'integrity'


class Name:
    def __init__(self, base, name_type=None):
        self.base = base
        self.name_type = name_type

    def __str__(self):
        return self.base


acquisitions = []   # every Credentials ever acquired, so tests can count them


class Credentials:
    # What a freshly acquired credential starts with. Acceptor credentials come
    # from a keytab and never expire, which MIT reports as an indefinite
    # lifetime; anything that can initiate holds an ordinary TGT with an
    # ordinary life. Modelled rather than stubbed, because the difference
    # between those two is the entire bug this models.
    INITIATE_LIFETIME = 86400

    def __init__(self, name=None, usage=None, store=None):
        self.name = name
        self.usage = usage
        self.store = store
        self._lifetime = None if usage == 'accept' else Credentials.INITIATE_LIFETIME
        acquisitions.append(self)

    @property
    def lifetime(self):
        """Seconds remaining, None when indefinite.

        An expired credential does NOT report zero: MIT raises when you inquire
        one. Code that only compares numbers would sail past an expired
        credential, so the fake raises here for the same reason the real thing
        does."""
        if self._lifetime is not None and self._lifetime <= 0:
            raise GSSError('Major (851968): The referenced credential has expired')
        return self._lifetime

    def expire(self):
        """Test hook: age this credential out, as nine days of uptime would."""
        self._lifetime = 0

    def impersonate(self, name, usage='initiate'):     # S4U2Self (not exercised)
        return Credentials(name=name, usage=usage)


# --- constrained delegation, modelled on measured behaviour -------------------
# These mirror what a real KDC did on the live stack, so the hermetic tests fail
# for the same reasons production would:
#   * usage='accept' NEVER yields a delegated credential, whatever the caller
#     sent. That is the MIT behaviour that made this look impossible at first.
#   * usage='both' (with a client_keytab) yields one NAMED FOR THE CALLER.
#   * asking for a target outside the realm's allowlist is refused by the KDC,
#     not by us, with KDC_ERR_BADOPTION. The message text matters: delegation.py
#     keys its audit slug off the word "option".
ALLOWED_TARGETS = set()          # what the KDC has been told to permit


def allow_target(spn):
    ALLOWED_TARGETS.add(spn)


class SecurityContext:
    _counter = 0

    def __init__(self, creds=None, usage=None, name=None, mech=None, flags=None):
        self.creds = creds
        self.usage = usage
        self.name = name
        self.requested_mech = mech
        self.flags = list(flags) if flags else []
        SecurityContext._counter += 1
        self.serial = SecurityContext._counter
        self._complete = False
        self._mech = None
        self._iname = None
        if usage == 'initiate':
            contexts.append(self)

    # Set by the test when it wants to simulate a delegating client; the real
    # thing carries this across the wire inside the token.
    flags_from_initiator = ()

    def step(self, token=None):
        if self.usage == 'accept':
            t = bytes(token or b'')
            if t.startswith(b'GOOD:'):
                self._complete = True
                self._mech = OID(_SPNEGO)
                self._iname = Name(t[5:].decode())
                return b''
            if t.startswith(b'BADMECH:'):
                self._complete = True
                self._mech = OID(_NTLM)
                self._iname = Name(t[8:].decode())
                return b''
            if t == b'INCOMPLETE':
                self._complete = False
                return b'continue'
            raise GSSError('defective token')
        # initiator
        base = getattr(self.name, 'base', '')
        # An initiator built from an evidence credential is a constrained
        # delegation request, so the KDC allowlist applies. Ordinary initiators
        # (the client bridge) carry no evidence and are unaffected.
        if getattr(self.creds, 'is_evidence', False) and base not in ALLOWED_TARGETS:
            raise GSSError(
                'Major (851968): Unspecified GSS failure.  Minor code may provide '
                'more information, Minor (2529638925): KDC can\'t fulfill requested option')
        ap_req = ('FAKE-AP-REQ:%s:%d' % (base, self.serial)).encode()
        if self.requested_mech == OID(_SPNEGO):
            return _spnego_token(ap_req)
        if self.requested_mech in (None, OID(_KRB5)):
            return _krb5_token(ap_req)
        raise GSSError('Major (65536): An unsupported mechanism was requested')

    @property
    def complete(self):
        return self._complete

    @property
    def mech(self):
        return self._mech

    @property
    def initiator_name(self):
        return self._iname

    @property
    def delegated_creds(self):
        """None unless the ACCEPTOR credential can also initiate. This is the
        whole behaviour the design turns on, so it is modelled rather than
        stubbed: a test that acquires usage='accept' must see None here, exactly
        as the live KDC gave us."""
        if not self._complete or self.usage != 'accept':
            return None
        if getattr(self.creds, 'usage', None) != 'both':
            return None
        cred = Credentials(name=self._iname, usage='initiate')
        cred.is_evidence = True          # marks it as subject to the allowlist
        # Which of the TWO credential kinds MIT would compose here. A caller who
        # sets delegate_to_peer gets their whole TGT (impersonator field EMPTY,
        # allowlist does not apply); one who does not gets a narrow evidence
        # credential stamped with the ACCEPTOR's own name. Modelled rather than
        # stubbed, because refusing the first is the control under test, and a
        # fake that only ever produced narrow credentials would let a regression
        # that accepts TGTs pass green. Matches live MIT krb5 1.20.1.
        if _flag_names(self.flags_from_initiator) & {'delegate_to_peer'}:
            cred.impersonator = None
        else:
            cred.impersonator = _principal_form(getattr(self.creds, 'name', None))
        return cred


_IMPERSONATOR_OID = '1.2.840.113554.1.2.2.5.14'


def _flag_names(flags):
    return {str(getattr(f, 'name', f)) for f in (flags or ())}


_FAKE_REALM = 'EXAMPLE.INTERNAL'


def _principal_form(name):
    """'HTTP@host' -> 'HTTP/host@REALM'. MIT reports the impersonator as a
    Kerberos principal, not in GSS hostbased form, and the check in
    server/delegation.py compares against a principal, so the fake must return
    what MIT returns rather than what is convenient to store."""
    if name is None:
        return None
    base = str(name)
    svc, sep, host = base.partition('@')
    if not sep:
        return base
    return '%s/%s@%s' % (svc, host, _FAKE_REALM)


class _Raw:
    """gssapi.raw, only the one call server/delegation.py makes.

    inquire_cred_by_oid(cred, GSS_KRB5_GET_CRED_IMPERSONATOR) returns a ONE-item
    sequence for a narrow evidence credential and an EMPTY one for anything else,
    which is exactly what MIT does and exactly what the check keys off."""

    @staticmethod
    def inquire_cred_by_oid(cred, oid):
        if getattr(oid, 'seq', None) != _IMPERSONATOR_OID:
            raise GSSError('unsupported oid')
        imp = getattr(cred, 'impersonator', None)
        return [imp.encode('utf-8')] if imp else []


raw = _Raw()


def reset():
    contexts.clear()
    acquisitions.clear()
    SecurityContext._counter = 0
    ALLOWED_TARGETS.clear()
    Credentials.INITIATE_LIFETIME = 86400
    WORKSTATION_MECHS[:] = [_KRB5]
