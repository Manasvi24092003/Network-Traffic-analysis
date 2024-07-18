#!/usr/bin/env python
# coding: utf-8

# In[1]:


# get_ipython().system('pip install xgboost')
# get_ipython().system('pip install imblearn')


# In[2]:


import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE
from sklearn.metrics import classification_report, roc_auc_score
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns


# In[3]:


df1 = pd.read_csv("Final Dataset.csv")


# In[4]:


df1.info()


# In[5]:


def check_blank_entries(df1):
    blank_entries = [entry for entry in df1 if all(value.strip() == '' for value in entry)]
    return blank_entries
blank_entries = check_blank_entries(df1)
print(blank_entries)


# In[6]:


import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import LabelEncoder , StandardScaler
import ipaddress
le = LabelEncoder()
df1['proto'] = le.fit_transform(df1['proto'])
df1['flag'] = le.fit_transform(df1['flag'])
# Convert IP addresses to numerical representations
def ip_to_int(ip_str):
    return int(ipaddress.ip_address(ip_str))

df1['src_ip'] = df1['src_ip'].apply(ip_to_int)
df1['dst_ip'] = df1['dst_ip'].apply(ip_to_int)


# In[7]:


df1.head(5)


# In[8]:


#No blank entries present
from sklearn.cluster import KMeans
selected_columns = ['src_ip', 'dst_ip', 'proto', 'size']
X = df1[selected_columns]

# Determine the number of clusters (e.g., k = 3)
k = 3

# Initialize the K-Means clustering model
kmeans = KMeans(n_clusters=k)

# Fit the model to the data
kmeans.fit(X)

# Get cluster labels for each data point
cluster_labels = kmeans.labels_

# Add cluster labels to the original DataFrame
df1['cluster'] = cluster_labels

# Print the clustered data
print(df1[['serial', 'time', 'src_ip', 'dst_ip', 'proto', 'size', 'cluster']])


# In[9]:


#addition of some more attributes 
# Count occurrences of 'src_ip', 'dst_ip', 'src_port', 'dst_port'
df1['src_ip_count'] = df1.groupby('src_ip')['src_ip'].transform('count')
df1['dst_ip_count'] = df1.groupby('dst_ip')['dst_ip'].transform('count')
df1['src_port_count'] = df1.groupby('src_port')['src_port'].transform('count')
df1['dst_port_count'] = df1.groupby('dst_port')['dst_port'].transform('count')

# Derived feature: data transfer rate (size over ttl)
df1['data_transfer_rate'] = df1['size'] / df1['ttl']

# Interaction features
df1['src_dst_ip_pair'] = df1['src_ip'].astype(str) + '-' + df1['dst_ip'].astype(str)
df1['Total'] = df1.groupby('src_dst_ip_pair')['src_dst_ip_pair'].transform('count')


# In[10]:


print(df1.columns)


# In[11]:


df1


# In[12]:


df1.info()


# In[13]:


#saving the preprocessed dataset to Device
#using updated dataset


# In[34]:


df = pd.read_csv("updated_data.csv")


# In[35]:


df.info()


# In[36]:


#df.info()


# In[37]:


#df.drop('serial', axis=1, inplace=True)


# In[38]:


df.drop('cluster', axis=1, inplace=True)


# In[39]:


df.drop('src_dst_ip_pair', axis=1, inplace=True)


# # data analysis

# In[40]:


import seaborn as sns
import matplotlib.pyplot as plt
x = df [['alert']]
y = df['alert']
counts = y.value_counts()
plt.pie(counts, autopct='%2.2f%%', labels=counts.index)
plt.show()


# In[41]:


corr_matrix = df.corr()

# correlation matrix using a heatmap
plt.figure(figsize=(10, 8))
sns.heatmap(corr_matrix, annot=True, cmap="coolwarm", square=True)
plt.title("Correlation Matrix")
plt.show()


# In[42]:


plt.figure(figsize=(10, 6))
sns.histplot(df['alert'], bins=20, kde=True)
plt.title('Histogram of alert')
plt.xlabel('time')
plt.ylabel('Frequency')
plt.show()


# In[43]:


import matplotlib.pyplot as plt
plt.figure(figsize=(16, 9))
plt.title('Unclustered Data')
plt.grid()
plt.xlabel('flag')
plt.ylabel('ttl')
plt.scatter(df1['flag'], df1['ttl'], color='red', marker='>')
plt.show()


# In[44]:


plt.figure(figsize=(8, 6))
plt.hist(df['alert'], bins=20, color='skyblue')
plt.xlabel('Alert')
plt.ylabel('Frequency')
plt.title('Distribution of Alert')
plt.grid(True)
plt.show()


# In[45]:


import seaborn as sns
sns.pairplot(df, vars=['alert', 'Total', 'flag', 'time'])
plt.show()


# In[46]:


#Model TRaining for anomaly detetction





# # In[48]:


# #MOdwl -10 - using k means with preprocessing pipeline using threshold value
# X = df.drop(columns=['alert'])
# y = df['alert']

# # Define numerical and categorical features
# numerical_features = ['src_port', 'dst_port', 'ttl', 'size', 'src_ip_count', 'dst_ip_count', 'src_port_count', 'dst_port_count', 'data_transfer_rate', 'Total']
# categorical_features = ['proto', 'flag', 'src_ip', 'dst_ip']

# # Define preprocessing pipeline
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', StandardScaler(), numerical_features),
#         ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
#     ])

# # Train-Test Split
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# # Apply preprocessing
# X_train_scaled = preprocessor.fit_transform(X_train)
# X_test_scaled = preprocessor.transform(X_test)
# kmeans = KMeans(n_clusters=2, random_state=42)  # Assuming 2 clusters: one for normal and one for anomalies
# kmeans.fit(X_train_scaled)

# # Predict the cluster assignments
# y_train_pred = kmeans.predict(X_train_scaled)
# y_test_pred = kmeans.predict(X_test_scaled)

# # Calculate the distance to the closest cluster center for the training data
# distances = kmeans.transform(X_train_scaled).min(axis=1)

# # Define a threshold for anomaly detection based on the distance to the cluster center
# threshold = np.percentile(distances, 75)  # Anomalies are data points far from the cluster center

# # Identify anomalies for training data
# y_train_anomalies = [1 if x > threshold else 0 for x in distances]

# # Calculate the distance to the closest cluster center for the test data
# test_distances = kmeans.transform(X_test_scaled).min(axis=1)

# # Identify anomalies for test data
# y_test_anomalies = [1 if x > threshold else 0 for x in test_distances]
# from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# # Print evaluation metrics for the training data
# print(f'Training Accuracy: {accuracy_score(y_train, y_train_anomalies)}')
# print(f'Training Confusion Matrix:\n{confusion_matrix(y_train, y_train_anomalies)}')
# print(f'Training Classification Report:\n{classification_report(y_train, y_train_anomalies)}')

# # Print evaluation metrics for the test data
# print(f'Test Accuracy: {accuracy_score(y_test, y_test_anomalies)}')
# print(f'Test Confusion Matrix:\n{confusion_matrix(y_test, y_test_anomalies)}')
# print(f'Test Classification Report:\n{classification_report(y_test, y_test_anomalies)}')


# In[49]:

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.ensemble import IsolationForest

X = df.drop(columns=['alert'])
y = df['alert']

# Define numerical and categorical features
numerical_features = ['src_port', 'dst_port', 'ttl', 'size', 'src_ip_count', 'dst_ip_count', 'src_port_count', 'dst_port_count', 'data_transfer_rate', 'Total']
categorical_features = ['proto', 'flag', 'src_ip', 'dst_ip']

# Define preprocessing pipeline
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numerical_features),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
    ])

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Apply preprocessing
X_train_scaled = preprocessor.fit_transform(X_train)
X_test_scaled = preprocessor.transform(X_test)

# Perform KMeans to cluster the data
kmeans = KMeans(n_clusters=157, random_state=42)
kmeans.fit(X_train_scaled)

# Transform the data to get cluster distances
X_train_clusters = kmeans.transform(X_train_scaled)  # Shape: (n_samples, n_clusters)
X_test_clusters = kmeans.transform(X_test_scaled)    # Shape: (n_samples, n_clusters)

# Check dimensions of the arrays
print(f'Shape of X_train_scaled: {X_train_scaled.shape}')
print(f'Shape of X_train_clusters: {X_train_clusters.shape}')
print(f'Shape of X_test_scaled: {X_test_scaled.shape}')
print(f'Shape of X_test_clusters: {X_test_clusters.shape}')

# Use KMeans distances for anomaly detection
distances_train = kmeans.transform(X_train_scaled).min(axis=1)
distances_test = kmeans.transform(X_test_scaled).min(axis=1)

# Train an Isolation Forest model
iso_forest = IsolationForest(contamination=0.01, random_state=42)
iso_forest.fit(distances_train.reshape(-1, 1))  # Reshape for correct input dimensions

# Predict anomalies
train_anomalies = iso_forest.predict(distances_train.reshape(-1, 1))
test_anomalies = iso_forest.predict(distances_test.reshape(-1, 1))

# Convert to 0 (normal) and 1 (anomaly)
train_anomalies = [1 if x == -1 else 0 for x in train_anomalies]
test_anomalies = [1 if x == -1 else 0 for x in test_anomalies]

# Convert back to DataFrame for comparison
y_test_anomalies = pd.Series(test_anomalies, index=X_test.index)

# Get the actual alert labels from the original data
y_test = y_test.reset_index(drop=True)  # Reset index for alignment

# Define the alert function
def alert(predictions, serials):
    alerts = []
    for pred, serial in zip(predictions, serials):
        alerts.append((pred, serial))
    return alerts

# Extract serials from the original data
serials_test = X_test['serial']

# Get the alerts
alerts = alert(test_anomalies, serials_test)

# Print comparison of the predicted anomalies vs. actual alerts
print("Anomaly Detection Metrics:")
print(f'Accuracy: {accuracy_score(y_test, y_test_anomalies)}')
print('Classification Report:')
print(classification_report(y_test, y_test_anomalies))
print('Confusion Matrix:')
print(confusion_matrix(y_test, y_test_anomalies))

# Print the alerts
print('Alerts:')
for alert_value, serial in alerts:
    print(f'Alert Value: {alert_value}, Serial: {serial}')

# In[47]:


#visualizing data for K means
# from sklearn.decomposition import PCA
# from sklearn.decomposition import TruncatedSVD

# X = df.drop(columns=['alert'])
# y = df['alert']
# #X_train_scaled = X_scaled
# #X_test_scaled = preprocessor.transform(X_test)
# # Perform PCA for visualization
# pca = PCA(n_components=2)
# X_train_pca = pca.fit_transform(X_train_scaled)

# # Get cluster centers
# centers = kmeans.cluster_centers_

# # Perform PCA on cluster centers
# centers_pca = pca.transform(centers)

# # Plotting the clusters
# plt.figure(figsize=(10, 7))
# plt.scatter(X_train_pca[:, 0], X_train_pca[:, 1], c=kmeans.labels_, cmap='viridis', marker='o', s=50, alpha=0.5)
# plt.scatter(centers_pca[:, 0], centers_pca[:, 1], c='red', s=200, alpha=0.75, marker='X', label='Centroids')
# plt.title('KMeans Clustering Results')
# plt.xlabel('PCA Component 1')
# plt.ylabel('PCA Component 2')
# plt.legend()
# plt.show()

# # In[30]:


# #model 12 - K measn clustering using Isolation forest
# from sklearn.ensemble import IsolationForest
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', StandardScaler(), numerical_features),
#         ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
#     ])

# # Train-Test Split
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# # Apply preprocessing
# X_train_scaled = preprocessor.fit_transform(X_train)
# X_test_scaled = preprocessor.transform(X_test)

# # Perform KMeans to cluster the data
# kmeans = KMeans(n_clusters=157, random_state=42)
# kmeans.fit(X_train_scaled)

# # Transform the data to get cluster distances
# X_train_clusters = kmeans.transform(X_train_scaled)  # Shape: (n_samples, n_clusters)
# X_test_clusters = kmeans.transform(X_test_scaled)    # Shape: (n_samples, n_clusters)

# # Check dimensions of the arrays
# print(f'Shape of X_train_scaled: {X_train_scaled.shape}')
# print(f'Shape of X_train_clusters: {X_train_clusters.shape}')
# print(f'Shape of X_test_scaled: {X_test_scaled.shape}')
# print(f'Shape of X_test_clusters: {X_test_clusters.shape}')

# # Use KMeans distances for anomaly detection
# distances_train = kmeans.transform(X_train_scaled).min(axis=1)
# distances_test = kmeans.transform(X_test_scaled).min(axis=1)

# # Train an Isolation Forest model
# iso_forest = IsolationForest(contamination=0.01, random_state=42)
# iso_forest.fit(distances_train.reshape(-1, 1))  # Reshape for correct input dimensions

# # Predict anomalies
# train_anomalies = iso_forest.predict(distances_train.reshape(-1, 1))
# test_anomalies = iso_forest.predict(distances_test.reshape(-1, 1))

# # Convert to 0 (normal) and 1 (anomaly)
# train_anomalies = [1 if x == -1 else 0 for x in train_anomalies]
# test_anomalies = [1 if x == -1 else 0 for x in test_anomalies]

# # Convert back to DataFrame for comparison
# y_test_anomalies = pd.Series(test_anomalies, index=X_test.index)

# # Get the actual alert labels from the original data
# y_test = y_test.reset_index(drop=True)  # Reset index for alignment

# # Print comparison of the predicted anomalies vs. actual alerts
# print("Anomaly Detection Metrics:")
# print(f'Accuracy: {accuracy_score(y_test, y_test_anomalies)}')
# print('Classification Report:')
# print(classification_report(y_test, y_test_anomalies))
# print('Confusion Matrix:')
# print(confusion_matrix(y_test, y_test_anomalies))


# # In[ ]:




# # model 9 - autoencoders
# import numpy as np
# import tensorflow as tf
# from tensorflow.keras.layers import Input, Dense
# from tensorflow.keras.models import Model

# # Define the autoencoder model
# input_dim = X_train.shape[1]  # Number of features
# inputs = Input(shape=(input_dim,))
# encoded = Dense(64, activation='relu')(inputs)  # Encoder
# encoded = Dense(32, activation='relu')(encoded)
# decoded = Dense(64, activation='relu')(encoded)  # Decoder
# decoded = Dense(input_dim, activation='sigmoid')(decoded)

# autoencoder = Model(inputs, decoded)
# autoencoder.compile(optimizer='adam', loss='mean_squared_error')

# # Train the autoencoder
# autoencoder.fit(X_train, X_train, epochs=20, batch_size=256, shuffle=True, validation_split=0.2, verbose=1)

# # Get the reconstruction loss
# reconstructed = autoencoder.predict(X_train)
# mse = np.mean(np.power(X_train - reconstructed, 2), axis=1)
# threshold = np.percentile(mse, 100 * 0.5)  # Set threshold for anomalies

# # Identify anomalies
# y_pred_binary = [1 if x > threshold else 0 for x in mse]

# # Evaluation
# from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# print(f'Accuracy: {accuracy_score(y_train, y_pred_binary)}')
# print(f'Confusion Matrix:\n{confusion_matrix(y_train, y_pred_binary)}')
# print(f'Classification Report:\n{classification_report(y_train, y_pred_binary)}')

# # In[ ]:


# #model 8 - +LocalOutlierFactor
# from sklearn.neighbors import LocalOutlierFactor
# from sklearn.preprocessing import StandardScaler

# # Assuming X_train is your feature matrix
# # Scale features
# scaler = StandardScaler()
# X_train_scaled = scaler.fit_transform(X_train)

# # Define and fit the model
# lof = LocalOutlierFactor(n_neighbors=20, contamination=0.005)  # Adjust n_neighbors and contamination
# y_pred = lof.fit_predict(X_train_scaled)

# # Convert predictions to binary format (1 for outliers, 0 for inliers)
# y_pred_binary = [1 if x == -1 else 0 for x in y_pred]

# # Evaluation
# from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# print(f'Accuracy: {accuracy_score(y_train, y_pred_binary)}')
# print(f'Confusion Matrix:\n{confusion_matrix(y_train, y_pred_binary)}')
# print(f'Classification Report:\n{classification_report(y_train, y_pred_binary)}')


# # In[ ]:


# #model 7 - Kmeans
# from sklearn.cluster import KMeans
# from sklearn.preprocessing import StandardScaler

# # Assuming X_train is your feature matrix
# # Scale features
# scaler = StandardScaler()
# X_train_scaled = scaler.fit_transform(X_train)

# # Define and fit the model
# kmeans = KMeans(n_clusters=2, random_state=42)  # Assuming 2 clusters, one for normal and one for anomalies
# kmeans.fit(X_train_scaled)
# y_pred = kmeans.predict(X_train_scaled)

# # Calculate the distance to the closest cluster center
# distances = kmeans.transform(X_train_scaled).min(axis=1)

# # Define a threshold for anomaly detection
# threshold = np.percentile(distances, 95)  # Anomalies are data points far from the cluster center

# # Identify anomalies
# y_pred_binary = [1 if x > threshold else 0 for x in distances]

# # Evaluation
# from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# print(f'Accuracy: {accuracy_score(y_train, y_pred_binary)}')
# print(f'Confusion Matrix:\n{confusion_matrix(y_train, y_pred_binary)}')
# print(f'Classification Report:\n{classification_report(y_train, y_pred_binary)}')


# # In[31]:


# #model 6 - svm
# from sklearn.svm import OneClassSVM
# from sklearn.preprocessing import StandardScaler

# # Assuming X_train is your feature matrix
# # Scale features
# scaler = StandardScaler()
# X_train_scaled = scaler.fit_transform(X_train)

# # Define and fit the model
# oc_svm = OneClassSVM(nu=0.005, kernel='rbf', gamma='auto')  # Adjust nu to set the upper bound on the fraction of outliers
# y_pred = oc_svm.fit_predict(X_train_scaled)

# # Convert predictions to binary format (1 for outliers, 0 for inliers)
# y_pred_binary = [1 if x == -1 else 0 for x in y_pred]

# # Evaluation
# from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# print(f'Accuracy: {accuracy_score(y_train, y_pred_binary)}')


# # In[ ]:


# #model 5 - Isolation forest
# from sklearn.ensemble import IsolationForest
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
# X = df.drop(columns=['alert'])
# X = StandardScaler().fit_transform(X)  # Standardize features

# # Define and fit the model
# iso_forest = IsolationForest(contamination=0.005, random_state=42)  # Set contamination to match the alert rate
# y_pred = iso_forest.fit_predict(X)

# # Convert predictions to binary format (1 for outliers, -1 for inliers)
# y_pred_binary = [1 if x == -1 else 0 for x in y_pred]

# # Evaluate the model
# print(f'Accuracy: {accuracy_score(y, y_pred_binary)}')
# print(f'Confusion Matrix:\n{confusion_matrix(y, y_pred_binary)}')
# print(f'Classification Report:\n{classification_report(y, y_pred_binary)}')

# import pandas as pd
# from sklearn.model_selection import StratifiedShuffleSplit
# from sklearn.metrics import accuracy_score

# # Assuming X and y are defined as pandas DataFrames

# sss = StratifiedShuffleSplit(n_splits=89, test_size=0.5, random_state=123)
# for train_index, test_index in sss.split(X, y):
#     X_train, X_test = X.iloc[train_index], X.iloc[test_index]
#     y_train, y_test = y.iloc[train_index], y.iloc[test_index]

#     # Train the model (replace 'model' with your actual model object)
#     model.fit(X_train, y_train)

#     # Predict and evaluate
#     y_pred = model.predict(X_test)
#     accuracy = accuracy_score(y_test, y_pred)
#     print('Accuracy:', accuracy)
# #Model2
# #pip install --upgrade scikit-learn imbalanced-learn
# from imblearn.pipeline import Pipeline  # Use imblearn.pipeline instead of sklearn.pipeline
# # Define features and target
# X = df.drop(columns=['alert'])
# y = df['alert']

# # Categorical and numerical features
# categorical_features = ['src_ip', 'dst_ip', 'proto', 'flag']
# numerical_features = ['src_port', 'dst_port', 'ttl', 'size', 'src_ip_count', 'dst_ip_count', 
#                       'src_port_count', 'dst_port_count', 'data_transfer_rate', 'Total', ]

# # Preprocessing
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', StandardScaler(), numerical_features),
#         ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)])
# smote = SMOTE(k_neighbors=1)  # Adjust this value based on your data

# # Define the model
# model = Pipeline(steps=[
#     ('preprocessor', preprocessor),
#     ('smote', smote),  # Handling imbalance with adjusted SMOTE
#     ('classifier', XGBClassifier(use_label_encoder=False, eval_metric='logloss'))])
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
# # Train the model
# model.fit(X_train, y_train)

# # Predict and evaluate
# y_pred = model.predict(X_test)
# print(classification_report(y_test, y_pred))

# # In[ ]:


# #model3
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
# from sklearn.model_selection import StratifiedShuffleSplit, StratifiedKFold
# import joblib

# # Select features and target
# features = ['alert', 'Total', 'src_ip_count', 'dst_ip_count']
# X = df[features]
# y = df['alert']

# # Initialize the model
# model = RandomForestClassifier(n_estimators=100, random_state=42)

# # Use Stratified K-Fold Cross Validation
# skf = StratifiedKFold(n_splits=5)
# accuracies = []
# precisions = []
# recalls = []
# f1s = []

# for train_index, test_index in skf.split(X, y):
#     X_train, X_test = X.iloc[train_index], X.iloc[test_index]
#     y_train, y_test = y.iloc[train_index], y.iloc[test_index]

#     # Train the model
#     model.fit(X_train, y_train)

#     # Predict and evaluate
#     y_pred = model.predict(X_test)
#     accuracies.append(accuracy_score(y_test, y_pred))
#     precisions.append(precision_score(y_test, y_pred))
#     recalls.append(recall_score(y_test, y_pred))
#     f1s.append(f1_score(y_test, y_pred))

# # Print evaluation metrics
# print(f'Accuracy: {sum(accuracies)/len(accuracies):.4f}')
# print(f'Precision: {sum(precisions)/len(precisions):.4f}')
# print(f'Recall: {sum(recalls)/len(recalls):.4f}')
# print(f'F1-Score: {sum(f1s)/len(f1s):.4f}')
# joblib.dump(model, 'trained_model.pkl')

# #model4
# # Select features and target
# features = ['alert', 'Total', 'src_ip_count', 'dst_ip_count']
# X = df[features]
# y = df['alert']

# # Initialize the model
# model = RandomForestClassifier(n_estimators=100, random_state=42)

# # Use Stratified K-Fold Cross Validation
# skf = StratifiedKFold(n_splits=5)
# accuracies = []
# precisions = []
# recalls = []
# f1s = []
# roc_aucs = []

# for train_index, test_index in skf.split(X, y):
#     X_train, X_test = X.iloc[train_index], X.iloc[test_index]
#     y_train, y_test = y.iloc[train_index], y.iloc[test_index]

#     # Train the model
#     model.fit(X_train, y_train)

#     # Predict and evaluate
#     y_pred = model.predict(X_test)
#     accuracies.append(accuracy_score(y_test, y_pred))
#     precisions.append(precision_score(y_test, y_pred))
#     recalls.append(recall_score(y_test, y_pred))
#     f1s.append(f1_score(y_test, y_pred))

#     # Calculate ROC AUC
#     y_prob = model.predict_proba(X_test)[:, 1] 
#     fpr, tpr, _ = roc_curve(y_test, y_prob)
#     roc_auc = auc(fpr, tpr)
#     roc_aucs.append(roc_auc)

#     # Print confusion matrix for this fold
#     cm = confusion_matrix(y_test, y_pred)
#     print(f'Confusion Matrix:\n{cm}\n')

# # Print evaluation metrics
# print(f'Accuracy: {sum(accuracies)/len(accuracies):.4f}')
# print(f'Precision: {sum(precisions)/len(precisions):.4f}')
# print(f'Recall: {sum(recalls)/len(recalls):.4f}')
# print(f'F1-Score: {sum(f1s)/len(f1s):.4f}')
# print(f'ROC AUC: {sum(roc_aucs)/len(roc_aucs):.4f}')

# # Plot ROC Curve for the last fold
# plt.figure(figsize=(10, 6))
# plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
# plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
# plt.xlim([0.0, 1.0])
# plt.ylim([0.0, 1.05])
# plt.xlabel('False Positive Rate')
# plt.ylabel('True Positive Rate')
# plt.title('Receiver Operating Characteristic')
# plt.legend(loc="lower right")
# plt.grid()
# plt.show()

# # Save the model
# joblib.dump(model, 'trained_model.pkl')

# # In[ ]:




