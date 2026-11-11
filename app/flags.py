FLAGS: list[tuple[str, str, str]] = [
    ('FI', '🇫🇮', 'Финляндия'),
    ('IT', '🇮🇹', 'Италия'),
    ('DE', '🇩🇪', 'Германия'),
    ('NL', '🇳🇱', 'Нидерланды'),
    ('FR', '🇫🇷', 'Франция'),
    ('GB', '🇬🇧', 'Великобритания'),
    ('US', '🇺🇸', 'США'),
    ('ES', '🇪🇸', 'Испания'),
    ('PL', '🇵🇱', 'Польша'),
    ('CZ', '🇨🇿', 'Чехия'),
    ('AT', '🇦🇹', 'Австрия'),
    ('CH', '🇨🇭', 'Швейцария'),
    ('SE', '🇸🇪', 'Швеция'),
    ('NO', '🇳🇴', 'Норвегия'),
    ('DK', '🇩🇰', 'Дания'),
    ('EE', '🇪🇪', 'Эстония'),
    ('LV', '🇱🇻', 'Латвия'),
    ('LT', '🇱🇹', 'Литва'),
    ('RU', '🇷🇺', 'Россия'),
    ('UA', '🇺🇦', 'Украина'),
    ('TR', '🇹🇷', 'Турция'),
    ('AE', '🇦🇪', 'ОАЭ'),
    ('SG', '🇸🇬', 'Сингапур'),
    ('JP', '🇯🇵', 'Япония'),
    ('KR', '🇰🇷', 'Корея'),
    ('HK', '🇭🇰', 'Гонконг'),
    ('TW', '🇹🇼', 'Тайвань'),
    ('KZ', '🇰🇿', 'Казахстан'),
    ('GE', '🇬🇪', 'Грузия'),
    ('CA', '🇨🇦', 'Канада'),
]

ISO_TO_EMOJI = {code: emoji for code, emoji, _name in FLAGS}
EMOJI_TO_ISO = {emoji: code for code, emoji, _name in FLAGS}
COUNTRY_NAMES = {code: name for code, _emoji, name in FLAGS}


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


def country_name(value: str) -> str:
    iso = to_iso(value)
    if iso:
        return COUNTRY_NAMES.get(iso, iso)
    return ''


def normalize_flags(value: str) -> str:
    seen: list[str] = []
    for part in (value or '').replace(';', ',').split(','):
        iso = to_iso(part.strip())
        if iso and iso not in seen:
            seen.append(iso)
    return ','.join(seen)


def flag_src(value: str) -> str:
    iso = to_iso(value)
    if not iso:
        return ''
    return f'/static/flags/{iso.lower()}.png'
