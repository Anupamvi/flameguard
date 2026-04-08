from app.config import Settings


def test_cors_origins_accepts_json_array_string():
    settings = Settings(cors_origins='["https://a.example","https://b.example"]')

    assert settings.parsed_cors_origins == ["https://a.example", "https://b.example"]


def test_cors_origins_accepts_bracketed_plain_list():
    settings = Settings(cors_origins='[https://a.example, https://b.example]')

    assert settings.parsed_cors_origins == ["https://a.example", "https://b.example"]


def test_cors_origins_accepts_comma_separated_string():
    settings = Settings(cors_origins='https://a.example, https://b.example')

    assert settings.parsed_cors_origins == ["https://a.example", "https://b.example"]


def test_trusted_proxy_cidrs_accepts_comma_separated_string():
    settings = Settings(trusted_proxy_cidrs='10.0.0.0/8, 192.168.0.0/16')

    assert [str(network) for network in settings.parsed_trusted_proxy_networks] == [
        "10.0.0.0/8",
        "192.168.0.0/16",
    ]