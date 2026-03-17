import json
import os
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def nsg_data():
    with open(FIXTURES_DIR / "azure_nsg_sample.json") as f:
        return json.load(f)


@pytest.fixture
def firewall_data():
    with open(FIXTURES_DIR / "azure_firewall_sample.json") as f:
        return json.load(f)


@pytest.fixture
def waf_data():
    with open(FIXTURES_DIR / "azure_waf_sample.json") as f:
        return json.load(f)
