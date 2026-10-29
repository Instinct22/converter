FLAGS: list[tuple[str, str]] = [
    ('FI', '🇫🇮'),
    ('IT', '🇮🇹'),
    ('DE', '🇩🇪'),
    ('NL', '🇳🇱'),
    ('FR', '🇫🇷'),
    ('GB', '🇬🇧'),
    ('US', '🇺🇸'),
    ('ES', '🇪🇸'),
    ('PL', '🇵🇱'),
    ('CZ', '🇨🇿'),
    ('AT', '🇦🇹'),
    ('CH', '🇨🇭'),
    ('SE', '🇸🇪'),
    ('NO', '🇳🇴'),
    ('DK', '🇩🇰'),
    ('EE', '🇪🇪'),
    ('LV', '🇱🇻'),
    ('LT', '🇱🇹'),
    ('RU', '🇷🇺'),
    ('UA', '🇺🇦'),
    ('TR', '🇹🇷'),
    ('AE', '🇦🇪'),
    ('SG', '🇸🇬'),
    ('JP', '🇯🇵'),
    ('KR', '🇰🇷'),
    ('HK', '🇭🇰'),
    ('TW', '🇹🇼'),
    ('KZ', '🇰🇿'),
    ('GE', '🇬🇪'),
    ('CA', '🇨🇦'),
]

ISO_TO_EMOJI = {code: emoji for code, emoji in FLAGS}
EMOJI_TO_ISO = {emoji: code for code, emoji in FLAGS}


def to_iso(value: str) -> str:
    raw = (value or '').strip()
    if len(raw) == 2 and raw.isalpha():
        return raw.upper()
    return EMOJI_TO_ISO.get(raw, '')


def to_emoji(value: str) -> str:
    iso = to_iso(value)
    if iso:
        return ISO_TO_EMOJI.get(iso, '')
    return (value or '').strip()


def flagcdn(value: str) -> str:
    iso = to_iso(value)
    if not iso:
        return ''
    return f'https://flagcdn.com/w40/{iso.lower()}.png'
