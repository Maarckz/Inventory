
from __future__ import annotations

from datetime import datetime

from flask import session

from utils.language import LANGUAGES

def translate(key, lang=None):
    if not lang:
        lang = session.get('language', 'pt')

    return LANGUAGES.get(lang, {}).get(key, LANGUAGES['pt'].get(key, key))

def inject_translations():
    return dict(
        translate=translate,
        language=session.get('language', 'pt')
    )

def formatar_data(data_iso):
    try:
        data = datetime.fromisoformat(data_iso)
        return data.strftime('%d/%m/%Y %H:%M')
    except (ValueError, TypeError):
        return data_iso
