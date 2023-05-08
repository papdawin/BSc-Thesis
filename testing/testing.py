import re
import numpy as np
from sklearn.cluster import KMeans
from sklearn.datasets import make_classification
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import average_precision_score, precision_score, recall_score, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier
import pandas as pd

def xss_test(df):
    data = df.query('attack_type == "XSS" or attack_type == "xss"')
    all = len(data)
    count = 0
    for index, row in data.iterrows():
        if re.compile(
                '(<)+(\s)*(script|body|img|image|irame|input|link|table|div|object|svg|html|iframe|video|audio|frameset)*.*(>)+',
                re.I).search(row[0]):
            count += 1
        else:
            print(row[0])
    print(f"Detected {count} from {all}")

def sql_test(df):
    data = df.query('attack_type == "sqli"')
    all = len(data)
    count = 0
    for index, row in data.iterrows():
        if re.compile(
                '([\x27]([\x27]|[^[\x27]])*)*.*(OR|AND|ALTER|WHERE|CREATE|DELETE|DROP|EXEC(UTE)?|INSERT( +INTO)?|MERGE|SELECT|UPDATE|UNION( +ALL)?|SLEEP.(\d*.))',
                re.I).search(row[0]):
            count += 1
        else:
            print(row[0])
    print(f"Detected {count} from {all}")

def pp_test(df):
    data = df.query('attack_type == "prototype_pollution"')
    all = len(data)
    count = 0
    for index, row in data.iterrows():
        if re.compile(
                '{*(\S|\s)*__proto__|constructor',
                re.I).search(row[0]):
            count += 1
        else:
            print(row[0])
    print(f"Detected {count} from {all}")

if __name__ == '__main__':
    df = pd.read_csv('./testing/payload_full.csv')

    # df2 = pd.read_fwf('./testing/xss-payload-list.txt', header=None, names=["payload"], delimiter="\n")
    # df2["label"] = 1
    # df2["attack_type"] = "XSS"
    # df = pd.concat([df1, df2])

    xss_test(df)
    sql_test(df)
    pp_test(df)

    # attributes = ['payload']
    # x_train, x_test, y_train, y_test = train_test_split(df[attributes], df['label'], test_size=0.2, stratify=df['label'], random_state=0)
    # x_train, x_dev, y_train, y_dev = train_test_split(x_train, y_train, test_size=0.2, stratify=y_train, random_state=0)
    # count_vectorizer = CountVectorizer(analyzer='char', min_df=10)
    # n_grams_train = count_vectorizer.fit_transform(x_train['payload'])
    # n_grams_dev = count_vectorizer.transform(x_dev['payload'])

    # SGDC
    # sgd = SGDClassifier(random_state=0)
    # sgd.fit(n_grams_train, y_train)
    # y_pred_sgd = sgd.predict(n_grams_dev)
    # print("Accuracy:", accuracy_score(y_dev, y_pred_sgd), "Precision", precision_score(y_dev, y_pred_sgd), "Recall", recall_score(y_dev, y_pred_sgd))
        # Accuracy: 0.9981751824817519 Precision 0.9993178717598908 Recall 0.9969377339231031
    # XGBC
    # xgb = XGBClassifier(seed=0)
    # xgb.fit(n_grams_train, y_train)
    # y_pred_sgd = xgb.predict(n_grams_dev)
    # print("Accuracy:", accuracy_score(y_dev, y_pred_sgd), "Precision", precision_score(y_dev, y_pred_sgd), "Recall", recall_score(y_dev, y_pred_sgd))
        # Accuracy: 0.9996682149966821 Precision 1.0 Recall 0.9993194964273563
    # LinearSVC
    # lsvc = LinearSVC(random_state=0, dual=False)
    # lsvc.fit(n_grams_train, y_train)
    # y_pred_sgd = lsvc.predict(n_grams_dev)
    # print("Accuracy:", accuracy_score(y_dev, y_pred_sgd), "Precision", precision_score(y_dev, y_pred_sgd), "Recall", recall_score(y_dev, y_pred_sgd))
        # Accuracy: 0.9998341074983411 Precision 1.0 Recall 0.9996597482136781

