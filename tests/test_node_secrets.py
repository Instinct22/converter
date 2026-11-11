from app.flags import country_name, normalize_flags
from app.routers.api import drop_blank_secrets


def test_blank_secrets_do_not_stay_in_the_patch():
    data = {
        'name': 'Austria-01',
        'api_token': '   ',
        'ssh_password': '',
        'ssh_user': ' ',
        'flag': 'AT',
    }
    drop_blank_secrets(data)
    assert data == {'name': 'Austria-01', 'flag': 'AT'}


def test_typed_secret_is_kept():
    data = {'api_token': 'kept-token', 'ssh_password': 'kept-pass', 'ssh_user': 'root'}
    drop_blank_secrets(data)
    assert data['api_token'] == 'kept-token'
    assert data['ssh_password'] == 'kept-pass'
    assert data['ssh_user'] == 'root'


def test_inbound_flags_keep_several_countries():
    assert normalize_flags('se, AT, se, 🇸🇪') == 'SE,AT'
    assert normalize_flags('') == ''
    assert normalize_flags('nope') == ''


def test_flag_title_is_the_country_name():
    assert country_name('AT') == 'Австрия'
    assert country_name('at') == 'Австрия'
    assert country_name('🇦🇹') == 'Австрия'
