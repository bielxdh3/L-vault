from localvault.whatsapp import parse_chat_text


def test_parse_whatsapp_lines():
    text = """[01/05/2026, 09:15:00] Ana: Bom dia
[01/05/2026, 09:16:12] Bruno: IMG-20260501-WA0001.jpg
05/01/26, 9:18 AM - Bruno: English format
continued"""
    messages = parse_chat_text(text)
    assert len(messages) == 3
    assert messages[0]["sender"] == "Ana"
    assert messages[1]["media_ref"] == "IMG-20260501-WA0001.jpg"
    assert "continued" in messages[2]["text"]
