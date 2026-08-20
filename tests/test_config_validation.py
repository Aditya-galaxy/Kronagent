import pytest
from kronagent.config import Settings, ConfigError


def test_settings_validation_valid_default():
    s = Settings()
    assert s.validate() == []
    s.validate_or_raise()


def test_settings_validation_invalid_values():
    s = Settings(
        sqs_wait_seconds=25,
        min_severity_for_containment=15.0,
        max_workers=0,
        trajectory_window_seconds=-5.0,
        trajectory_max_auto_executions=0,
        trajectory_max_scope_violations=0,
    )
    errors = s.validate()
    assert len(errors) == 6
    assert "KRONAGENT_SQS_WAIT_SECONDS" in errors[0]
    assert "KRONAGENT_MIN_SEVERITY" in errors[1]
    assert "KRONAGENT_MAX_WORKERS" in errors[2]
    assert "KRONAGENT_TRAJECTORY_WINDOW_SECONDS" in errors[3]
    assert "KRONAGENT_TRAJECTORY_MAX_AUTO" in errors[4]
    assert "KRONAGENT_TRAJECTORY_MAX_SCOPE_VIOLATIONS" in errors[5]

    with pytest.raises(ConfigError) as exc_info:
        s.validate_or_raise()
    assert "Invalid Kronagent configuration" in str(exc_info.value)
