from sklearn.preprocessing import OrdinalEncoder
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB, CategoricalNB
from sklearn.neighbors import KNeighborsClassifier

# Utility for combining two sets of classifications
def combine(class1: list[int], class2: list[int]):
  if len(class1) != len(class2):
    raise Exception('Different length')
  return [[class1[i], class2[i]] for i in range(len(class1))]

# Import KDD Cup dataset
raw_data = open('kddcup.data_10_percent.txt').read()
all_rows = [row.removesuffix('.').split(',') for row in raw_data.split('\n')[:-1]]
filtered_rows = [row for row in all_rows if len(row) == 42]

X_continuous = [[float(row[0])] + [float(col) for col in row[4:-1]] for row in filtered_rows]
enc = OrdinalEncoder()
X_categorical = enc.fit_transform([row[1:4] for row in filtered_rows])
y = [result[0] for result in OrdinalEncoder().fit_transform([[row[-1]] for row in filtered_rows])]

random_state = 0
train_size = 0.8
X_continuous_train, X_continuous_test, y_train, y_test = train_test_split(X_continuous, y, train_size=train_size, random_state=random_state)
X_categorical_train, X_categorical_test, _, _ = train_test_split(X_categorical, y, train_size=train_size, random_state=random_state)

total_test = len(X_continuous_test)

# K Nearest Neighbor (slow, about 10 minutes)
if False:
  neigh = KNeighborsClassifier(n_neighbors=3, algorithm='kd_tree')
  neigh.fit(X_continuous_train, y_train)
  y_knn_pred = neigh.predict(X_continuous_test)
  incorrect_test = (y_test != y_knn_pred).sum()
  print(f"K Nearest Neighbor: {incorrect_test}/{total_test} points mislabeled ({100 - incorrect_test / total_test * 100}% correct)")

# Categorical Naive Bayes
cnb = CategoricalNB()
y_categorical_pred = cnb.fit(X_categorical_train, y_train).predict(X_categorical_test)
incorrect_test = (y_test != y_categorical_pred).sum()
print(f"Categorical Naive Bayes: {incorrect_test}/{total_test} points mislabeled ({100 - incorrect_test / total_test * 100}% correct)")

# KNN + CNB (very slow, about 45 minutes)
if False:
  result_knn_cnb = CategoricalNB()
  y_train_knn = neigh.predict(X_continuous_train)
  y_train_cnb = cnb.predict(X_categorical_train)
  result_knn_cnb.fit(combine(y_train_knn, y_train_cnb), y_train)

  y_knn_cnb = result_knn_cnb.predict(combine(y_knn_pred, y_categorical_pred))
  incorrect_test = (y_test != y_knn_cnb).sum()
  print(f"Combined Naive Bayes: {incorrect_test}/{total_test} points mislabeled ({100 - incorrect_test / total_test * 100}% correct)")

# Gaussian Naive Bayes
gnb = GaussianNB()
y_continuous_pred = gnb.fit(X_continuous_train, y_train).predict(X_continuous_test)
incorrect_test = (y_test != y_continuous_pred).sum()
print(f"Gaussian Naive Bayes: {incorrect_test}/{total_test} points mislabeled ({100 - incorrect_test / total_test * 100}% correct)")

# Combined Naive Bayes
result_cnb = CategoricalNB()
y_train_continuous_pred = gnb.predict(X_continuous_train)
y_train_categorical_pred = cnb.predict(X_categorical_train)
result_cnb.fit(combine(y_train_continuous_pred, y_train_categorical_pred), y_train)

y_combined_pred = result_cnb.predict(combine(y_continuous_pred, y_categorical_pred))
incorrect_test = (y_test != y_combined_pred).sum()
print(f"Combined Naive Bayes: {incorrect_test}/{total_test} points mislabeled ({100 - incorrect_test / total_test * 100}% correct)")

# Combined Naive Bayes with probability
def combine_proba(continuous, categorical):
  if len(continuous) != len(categorical):
    raise Exception('Different length')
  return [continuous[i] + categorical[i] for i in range(len(continuous))]

result_gnb = GaussianNB()
y_train_continuous_pred = gnb.predict_proba(X_continuous_train)
y_train_categorical_pred = cnb.predict_proba(X_categorical_train)
result_gnb.fit(combine_proba(y_train_continuous_pred, y_train_categorical_pred), y_train)

y_combined_pred = result_gnb.predict(combine_proba(gnb.predict_proba(X_continuous_test), cnb.predict_proba(X_categorical_test)))
incorrect_test = (y_test != y_combined_pred).sum()
print(f"Combined Naive Bayes 2: {incorrect_test}/{total_test} points mislabeled ({100 - incorrect_test / total_test * 100}% correct)")

