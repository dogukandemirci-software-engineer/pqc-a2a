import pytest
from pqc_a2a import AgentIdentity, ReplayCache, open_envelope, seal, tamper

@pytest.fixture
def pair(): return AgentIdentity('a'), AgentIdentity('b')

def test_roundtrip_and_replay(pair):
    a,b=pair; env=seal(a,b,{'action':'delegate','value':42}); cache=ReplayCache()
    assert open_envelope(b,a,env,cache)=={'action':'delegate','value':42}
    with pytest.raises(ValueError, match='replay'): open_envelope(b,a,env,cache)

def test_tamper_fails(pair):
    a,b=pair; env=seal(a,b,{'x':'safe'})
    with pytest.raises(ValueError): open_envelope(b,a,tamper(env))

def test_identity_binding(pair):
    a,b=pair; other=AgentIdentity('other'); env=seal(a,b,{'x':1})
    with pytest.raises(ValueError): open_envelope(other,a,env)
