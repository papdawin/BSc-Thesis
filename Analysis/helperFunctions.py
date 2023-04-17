from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier
import pandas as pd
from io import StringIO
import email
import json
import re
from Data import config

df = pd.read_csv("Data/payload_full.csv", on_bad_lines='skip')

attributes = ['payload']
x_train, x_test, y_train, y_test = train_test_split(df[attributes], df['label'], test_size=0.01, stratify=df['label'], random_state=0)

count_vectorizer = CountVectorizer(analyzer='char', min_df=20)
xgb = XGBClassifier(seed=0)
pipeline = Pipeline([
    ('count_vectorizer', count_vectorizer),
    ('xgb', xgb)
])

pipeline.fit(x_train['payload'], y_train)

def contains_vector(part: str, part_name: str):
    ruleset = json.loads(config['ruleset'].get('manual_rules').replace("'", '"'))
    for rule in ruleset:
        if re.compile(rule['regex'], re.I).search(part):
            return f"Trace of {rule['name']} detected in {part_name}"
    return None

def format_request(data: bytes) -> dict:
    decoded = data.decode()
    status_line, request = decoded.split('\r\n', 1)
    headers, body = request.split('\r\n\r\n', 1)
    message = email.message_from_file(StringIO(headers))
    request = dict(message.items())
    request["body"] = body
    request["status_line"] = status_line
    return request
