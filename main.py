from threading import Thread

from Analysis import *
from Proxy import *
from Data import config
import json

class WAFProxy:
    def __init__(self, start_address: str, end_address: str, start_port: int, end_port: int, message_size: int):
        self.start_address = start_address
        self.start_port = start_port
        self.message_size = message_size
        self.server_instance = ServerInstanceHandler(end_address, end_port, message_size)
    def client_proxy_connection(self, client_connection: ClientInstanceHandler) -> None:
        client_connection.forward_comm(self.server_instance)
    def handle_communication(self):
        while True:
            try:
                client_connection = ClientInstanceHandler(self.start_address, self.start_port, self.message_size)
                Thread(target=self.client_proxy_connection, args=[client_connection]).start()
            except InvalidIPException:
                pass


if __name__ == '__main__':
    # print("is safe:",
    #       analyze_request(
    #           b'GET /login.php HTTP/1.1\r\nContent-Type: application/json\r\nUser-Agent: PostmanRuntime/7.32.2\r\nAccept: */*\r\nPostman-Token: 839f78d8-9347-4fcd-8891-de30321d34b4\r\nHost: localhost:8080\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nContent-Length: 19\r\nCookie: Cookie_1=value; PHPSESSID=ljmsk81erv9c93l19o3d2p2mq3; security=low\r\n\r\n{"__proto__":"asd"}',
    #           ["192.168.1.31", 0]))
    # print("is safe:",
    #       analyze_request(
    #           b'GET /login.php HTTP/1.1\r\nContent-Type: application/json\r\nUser-Agent: PostmanRuntime/7.32.2\r\nAccept: */*\r\nPostman-Token: 839f78d8-9347-4fcd-8891-de30321d34b4\r\nHost: localhost:8080\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nContent-Length: 19\r\nCookie: Cookie_1=value; PHPSESSID=ljmsk81erv9c93l19o3d2p2mq3; security=low\r\n\r\n',
    #           ["192.168.1.31", 0]))


    # df = pd.read_csv("Data/payload_full.csv", on_bad_lines='skip')
    # # df.info()
    # # print(df['label'].value_counts())
    # print(df.head())
    # attributes = ['payload']
    # x_train, x_test, y_train, y_test = train_test_split(df[attributes], df['label'], test_size=0.2,
    #                                                     stratify=df['label'], random_state=0)
    # x_train, x_dev, y_train, y_dev = train_test_split(x_train, y_train, test_size=0.2,
    #                                                   stratify=y_train, random_state=0)
    # print('Train:', len(y_train), 'Dev:', len(y_dev), 'Test:', len(y_test))
    #
    # count_vectorizer = CountVectorizer(analyzer='char', min_df=10)
    # xgb = XGBClassifier(seed=0)
    # pipeline = Pipeline([
    #     ('count_vectorizer', count_vectorizer),
    #     ('xgb', xgb)
    # ])
    #
    # pipeline.fit(x_train['payload'], y_train)
    # y_pred = pipeline.predict(x_dev['payload'])
    # y_pred_proba = pipeline.predict_proba(x_dev['payload'])
    #
    # print('Average precision:', average_precision_score(y_dev, y_pred_proba[:, 1]))
    # print('Precision:', precision_score(y_dev, y_pred))
    # print('Recall:', recall_score(y_dev, y_pred))
    #
    #
    # def get_top_k_indices(l, k=10):
    #     ind = np.argpartition(l, -k)[-k:]
    #     return ind[np.argsort(l[ind])[::-1]]
    #
    #
    # feature_names = {v: k + ' (n_gram)' for k, v in count_vectorizer.vocabulary_.items()}
    # for idx in get_top_k_indices(xgb.feature_importances_, 10):
    #     print('Importance: {:.3f} Feature: {}'.format(xgb.feature_importances_[idx], feature_names[idx]))
    #
    # print(pipeline.predict(["GET /login.php HTTP/1.1"]))
    # print(pipeline.predict(["Cookie_1=value"]))
    # print(pipeline.predict(["Rodriguez"]))

    # n_grams_train = count_vectorizer.fit_transform(x_train['payload'])
    # n_grams_dev = count_vectorizer.transform(x_dev['payload'])
    #
    # print('Number of features:', len(count_vectorizer.vocabulary_))
    # Number of features: 62

    p = WAFProxy(
        start_address=config['base']['accept_from'],
        end_address=config['base']['local_IP'],
        start_port=int(config['base']['in_port']),
        end_port=int(config['base']['out_port']),
        message_size=2**12
    )
    p.handle_communication()

