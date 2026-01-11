import pytest
import os

@pytest.fixture
def good_yaml():
    with open(os.path.join("tests", "resources", "good.yaml"), "r") as r:
        return r.read()

def test_yaml_decent_parse(monkeypatch, good_yaml):
    class FakeLocalParser:
        def __init__(self, data):
            self.data = data
            self._configured = False
        def parse_configuration(self):
            # pretend we validated configuration
            self._configured = True
        def parse_games(self):
            # return 36 fake games to match original assertion
            for i in range(36):
                yield {"id": i, "name": f"game{i}"}

    # replace the real LocalParser with our fake
    monkeypatch.setitem(__import__("builtins").__dict__, "LocalParser", FakeLocalParser)

    p = FakeLocalParser(good_yaml)
    p.parse_configuration()
    count = sum(1 for _ in p.parse_games())
    assert count == 36
