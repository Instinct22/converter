import json

from markupsafe import escape

from app.routers.ui import script_json


def test_script_json_stays_valid_inside_a_script_tag():
    payload = [{'id': 1, 'name': 'EE "01" </script>', 'enabled': True}]
    dumped = script_json(payload)
    assert escape(dumped) == dumped
    text = str(dumped)
    assert '&#34;' not in text
    assert '</script>' not in text
    assert json.loads(text) == payload
