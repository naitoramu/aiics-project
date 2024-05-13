from pyspark.sql import SparkSession
from pyspark.sql.functions import substring_index, split, to_timestamp, col

spark = SparkSession.builder \
    .appName("Script") \
    .getOrCreate()


# df = spark.read.csv('Edge/Edge-IIoTset dataset/Normal traffic/combined.csv', header=True)
# df = spark.read.csv('Edge/Edge-IIoTset dataset/Attack traffic/Port_Scanning_attack.csv', header=True)
df = spark.read.csv('Edge/Edge-IIoTset dataset/Attack traffic/DDoS_TCP_SYN_Flood_attack.csv', header=True)

start_timestamp = '2024-05-13 16:00:00.000000'
end_timestamp = '2024-05-13 19:06:00.000000'

df = df \
    .withColumn("frame.time", to_timestamp(split("`frame.time`", " ").getItem(2))) \
    .filter(col("`frame.time`").isNotNull() & (col("`frame.time`") >= start_timestamp) & (col("`frame.time`") <= end_timestamp)) \
    .orderBy(col("`frame.time`"))

df.coalesce(1).write.csv('ddos-tcp-syn-flood-dir', header=True)

spark.stop()