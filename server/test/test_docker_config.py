from pathlib import Path
import yaml


def test_database_port_is_not_exposed():
    compose_file = Path(__file__).parent.parent.parent / "docker-compose.yml"

    with open(compose_file) as f:
        compose = yaml.safe_load(f)

    db_service = compose["services"]["db"]

    assert "ports" not in db_service