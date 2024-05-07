# This Python 3 environment comes with many helpful analytics libraries installed
# It is defined by the kaggle/python Docker image: https://github.com/kaggle/docker-python
# For example, here's several helpful packages to load

import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import warnings
#df = df.reset_index()
warnings.filterwarnings('ignore')

#Settings
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
# Input data files are available in the read-only "../input/" directory
# For example, running this (by clicking run or pressing Shift+Enter) will list all files under the input directory
cols = [' Bwd Packet Length Std',' PSH Flag Count',' min_seg_size_forward',' Min Packet Length',' ACK Flag Count',' Bwd Packet Length Min',' Fwd IAT Std','Init_Win_bytes_forward',' Flow IAT Max',' Bwd Packets/s',' URG Flag Count','Bwd IAT Total',' Label']

benign_df = pd.read_csv(r'archive_3\MachineLearningCSV\MachineLearningCVE\benign_monday.csv')
attack_df = pd.read_csv(r'archive_3\MachineLearningCSV\MachineLearningCVE\malicious_Wednesday.csv')
benign_df2 = pd.read_csv(r'archive_3\MachineLearningCSV\MachineLearningCVE\benign_friday.csv')
attack_df2 = pd.read_csv(r'archive_3\MachineLearningCSV\MachineLearningCVE\malicious_Friday.csv')
SlowLoris=pd.read_csv(r'archive_3\MachineLearningCSV\MachineLearningCVE\SlowLoris1.csv')
SlowPost=pd.read_csv(r'archive_3\MachineLearningCSV\MachineLearningCVE\SlowPost1.csv')
SlowRead=pd.read_csv(r'archive_3\MachineLearningCSV\MachineLearningCVE\SlowRead1.csv')
Hulk=pd.read_csv(r'archive_3\MachineLearningCSV\MachineLearningCVE\Hulk1.csv')
#print("Benign Dataset:")
#print(benign_df.info())

#print("\nAttack Dataset:")
#print(attack_df.info())

# Display a few rows of each dataset
#print("\nBenign Dataset Sample:")
#print(benign_df.head())

#print("\nAttack Dataset Sample:")
#print(attack_df.head())

df = pd.concat([benign_df,attack_df,benign_df2,attack_df2,Hulk,SlowPost,SlowRead,SlowLoris])
del benign_df,attack_df


def clean_dataset(df):
    assert isinstance(df, pd.DataFrame), "df needs to be a pd.DataFrame"
    df.dropna(inplace=True)
    indices_to_keep = df.isin([np.nan, np.inf, -np.inf]).any(axis=1)
    return df[indices_to_keep].astype(np.float64)
data = df.copy()

y = data['Label'].copy()
X = data.drop(['Label'],axis=1)

print("data loaded successfully")
df.head()
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib
# Drop rows with NaN values
data.dropna(inplace=True)

# Handle infinite values
data.replace([np.inf, -np.inf], np.nan, inplace=True)
data.dropna(inplace=True)

# Separate features and labels again
#vectorizer = TfidfVectorizer(stop_words='english', encoding='ISO-8859-1')

#samples = attack_df + benign_df
#X = vectorizer.fit_transform(samples).toarray()
y = data['Label'].copy()
X = data.drop(['Label'], axis=1)
#y = np.concatenate((np.ones(len(attack_df)), np.zeros(len(benign_df))))
print("data cleaned successfully")
random_state = np.random.randint(1000)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=random_state)

# Split the dataset into training and testing sets
def train_and_evaluate():
            
            print("module is training")
            print("random_state :",random_state)


            clf = RandomForestClassifier(n_estimators=100, random_state=42)
            clf.fit(X_train, y_train)

            accuracy = clf.score(X_test, y_test)
            #vectorizer = TfidfVectorizer(stop_words='english', encoding='ISO-8859-1')
            #vectorizer.fit(X_train)
			
            return clf, accuracy
if os.path.exists('saved_model.joblib'):
    clf = joblib.load('saved_model.joblib')
    print('Loaded saved model!')
    test_df = pd.read_csv("2024-03-17_Flow.csv")
    test_df.dropna(inplace=True)

# Handle infinite values
    test_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    test_df.dropna(inplace=True)

    # Clean the test data (if needed)
    #test_df_cleaned = clean_dataset(test_df)
    
    # Separate features and labels for the test data
    #y_test = test_df_cleaned['Label'].copy()
    #X_test = test_df_cleaned.drop(['Label'], axis=1)
    
    # Make predictions
    predictions = clf.predict(test_df)
    for idx, prediction in enumerate(predictions):
        print(prediction,idx)

    # Evaluate the model
#     accuracy = accuracy_score(y_test, predictions)
#     print("Accuracy on test data:", accuracy)
#     print(confusion_matrix(y_test, predictions))
#     print(classification_report(y_test, predictions))
#     # test_df = pd.read_csv("sss.csv")
#     # vectorizer = TfidfVectorizer(stop_words='english', encoding='ISO-8859-1')
#     # vectorizer.fit(X_train)
#     # X_test = vectorizer.transform(test_df).toarray()
#     # predictions = clf.predict(X_test)
#     # print(predictions)
#   # Replace "path_to_your_csv_file.csv" with the actual path

# # Preprocess the data (assuming it's similar to the training data)
# # For example, drop any NaN values and convert text columns to numeric using TF-IDF vectorizer
# # Make sure to handle missing values and any other preprocessing steps that were done on the training data

# # Load the TF-IDF vectorizer
	
# 	  # Assuming X_train is the training data used to fit the vectorizer

# # Transform the test data using the fitted vectorizer
	

# # Make predictions
	

# # Display the predictions
	
else:
    boudy=True
    while boudy:
          
        clf, accuracy = train_and_evaluate()
        print("Accuracy: ", accuracy)
        #print(int(accuracy))                       # save the model if accuracy is 1.00
        #if int(accuracy) == 1:
        joblib.dump(clf, 'saved_model.joblib')
        print('Saved model!')
        boudy=False
        
#         test_df = pd.read_csv("sss.csv")
#         vectorizer = TfidfVectorizer(stop_words='english', encoding='ISO-8859-1')
#         vectorizer.fit(X_train)
#         X_test = vectorizer.transform(test_df).toarray()
#         predictions = clf.predict(X_test)
#         print(predictions)
#         break

#with open("sss.csv", "rb") as f:
                #sample = f.read()
                #pred = clf.predict(vectorizer.transform([sample]).toarray())[0]
                #result = "%s: %s" % ("sss.csv", "malware" if pred == 1 else "benign")
                #print(result)

# Evaluate the model

