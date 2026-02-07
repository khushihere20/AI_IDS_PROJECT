import pandas as pd
import pytest

from encoders import (
    encode_column,
    encode_dataframe,
    PROTOCOL_MAP,
    SERVICE_MAP,
    FLAG_MAP
)

# ---------- Fixtures ----------

@pytest.fixture
def valid_df():
    return pd.DataFrame({
        "duration": [0, 1],
        "protocol_type": ["tcp", "udp"],
        "service": ["http", "ftp_data"],
        "flag": ["SF", "SF"],
        "src_bytes": [100, 200],
        "dst_bytes": [300, 400]
    })


@pytest.fixture
def invalid_protocol_df():
    return pd.DataFrame({
        "protocol_type": ["tcp", "bluetooth"]
    })


# ---------- Tests for encode_column ----------

def test_encode_column_success():
    df = pd.DataFrame({"protocol_type": ["tcp", "udp", "icmp"]})
    encoded = encode_column(df, "protocol_type", PROTOCOL_MAP)

    assert encoded.tolist() == [0, 1, 2]


def test_encode_column_unknown_value_raises_error():
    df = pd.DataFrame({"protocol_type": ["tcp", "unknown"]})

    with pytest.raises(ValueError) as exc:
        encode_column(df, "protocol_type", PROTOCOL_MAP)

    assert "Unknown values in 'protocol_type'" in str(exc.value)


# ---------- Tests for encode_dataframe ----------

def test_encode_dataframe_success(valid_df):
    encoded_df = encode_dataframe(valid_df.copy())

    assert encoded_df["protocol_type"].dtype.kind in "iu"
    assert encoded_df["service"].dtype.kind in "iu"
    assert encoded_df["flag"].dtype.kind in "iu"


def test_encode_dataframe_preserves_row_count(valid_df):
    encoded_df = encode_dataframe(valid_df.copy())

    assert len(encoded_df) == len(valid_df)


def test_encode_dataframe_unknown_service_fails():
    df = pd.DataFrame({
        "protocol_type": ["tcp"],
        "service": ["unknown_service"],
        "flag": ["SF"]
    })

    with pytest.raises(ValueError):
        encode_dataframe(df)