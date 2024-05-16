import pandas as pd
from datetime import datetime, timedelta


class LogParser:

    @staticmethod
    def logs_to_series(df, logs_per_bucket):
        df['frame.time'] = df['frame.time'].astype('int64') / 10**9
        buckets = []

        for i in range(0, df.shape[0], logs_per_bucket):
            bucket = df.iloc[i:i + logs_per_bucket]
            bucket['frame.time'] = bucket['frame.time'] - bucket['frame.time'].iloc[0]
            buckets.append(bucket)

        return buckets
