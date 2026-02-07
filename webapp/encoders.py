# encoders.py

PROTOCOL_MAP = {
    'tcp': 0,
    'udp': 1,
    'icmp': 2
}

SERVICE_MAP = {
    'http': 0,
    'ftp_data': 1,
    'domain_u': 2,
    'smtp': 3,
    'private': 4,
    'ecr_i': 5
}

FLAG_MAP = {
    'SF': 0
}


def encode_column(df, column, mapping):
    unknown = set(df[column].unique()) - set(mapping.keys())
    if unknown:
        raise ValueError(f"Unknown values in '{column}': {unknown}")
    return df[column].map(mapping)


def encode_dataframe(df):
    """
    Applies all categorical encodings required for IDS inference.
    """
    df['protocol_type'] = encode_column(df, 'protocol_type', PROTOCOL_MAP)
    df['service'] = encode_column(df, 'service', SERVICE_MAP)
    df['flag'] = encode_column(df, 'flag', FLAG_MAP)

    return df