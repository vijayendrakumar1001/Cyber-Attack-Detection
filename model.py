import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from sklearn.model_selection import train_test_split
from sklearn.datasets import make_classification
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import joblib
import pandas as pd

data = pd.read_csv('datasetforproject_UPDATED.csv')
features = ['L4_SRC_PORT', 'TCP_FLAGS', 'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO']
target = 'Label'

X = data[features]
y = data[target]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)


model = Sequential()
model.add(Dense(units=4, activation='relu', input_dim=X_train.shape[1]))
model.add(Dense(units=1, activation='sigmoid'))

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

model.fit(X_train, y_train, epochs=10,batch_size=128, validation_split=0.2)
y_pred = model.predict(X_test)
y_pred = (y_pred > 0.5)

joblib.dump(model,'model.joblib')