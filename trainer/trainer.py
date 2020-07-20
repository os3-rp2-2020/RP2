import numpy as np
import pandas as pd

from joblib import dump

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn import metrics

from sklearn_rvm import EMRVC

class DNSReputationTrainer():
    def __init__(self):
        self.classifier = EMRVC(kernel="rbf", gamma="auto")

    def train(self, malicious_domains, benign_domains):
        combined = np.array(malicious_domains + benign_domains)
        malicious = np.array(malicious_domains)
        benign = np.array(benign_domains)

        labels = []

        for _ in malicious:
            labels.append("malicious")

        for _ in benign:
            labels.append("benign")

        x = pd.DataFrame({
            "num_ns": combined[:, 0],
            "num_mx": combined[:, 1],
            "num_txt": combined[:, 2],
            "entropy": combined[:, 3],
            "registration_period": combined[:, 4],
        })

        y = labels

        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.20, random_state = 0)

        sc_X = StandardScaler()
        x_train = sc_X.fit_transform(x_train)
        x_test = sc_X.transform(x_test)

        self.classifier.fit(x_train, y_train)

        y_pred = self.classifier.predict(x_test)
        print("Accuracy: " + metrics.accuracy_score(y_test, y_pred))

    def save(self, location):
        dump(self.classifier, location)

