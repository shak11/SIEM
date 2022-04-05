from sklearn import preprocessing as pre
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import pandas as pd
import consts as c


def load_df(what):
    if what == "FW":
        return pd.read_csv(c.FW_FILE_NAME)
    elif what == "WIN":
        return pd.read_csv(c.WIN_FILE_NAME)


def df_convert_str_to_numeric(df):
    le = pre.LabelEncoder()
    for i in range(df.shape[1]):
        df[:, i] = le.fit_transform(df[:, i])
    return df


def get_attacks(df, features):
    # print("Data Shape : ", df.shape)
    # print(df.head())

    # Set featured columns
    features = df.loc[:, features].values
    # Parse string to int pre preparation for model StandardScaler
    features = df_convert_str_to_numeric(features)

    features = StandardScaler().fit_transform(features)  # normalizing the features

    feat_cols = ['feature' + str(i) for i in range(features.shape[1])]
    normalised = pd.DataFrame(features, columns=feat_cols)
    pca = PCA(n_components=2)
    principal_components = pca.fit_transform(normalised)
    # Set REAL COMPONENT NAME
    principal_df = pd.DataFrame(data=principal_components, columns=['component 1', 'component 2'])
    return principal_df


def get_min_max(ml):
    # Set min and max
    min_x = ml.loc[0][0]
    max_x = ml.loc[0][0]
    min_y = ml.loc[0][1]
    max_y = ml.loc[0][1]
    # Range where MORE suspicious
    # range_x = 0.2
    # range_y = 0.05
    # Range where suspicious
    range_x = 0.7
    range_y = 0.05

    for row_index in ml.iterrows():
        row_index = row_index[1]
        if min_x - range_x <= row_index[0] <= max_x + range_x:
            if row_index[0] < min_x:
                min_x = row_index[0]
            elif row_index[0] > max_x:
                max_x = row_index[0]

        if min_y - range_y <= row_index[1] <= max_y + range_y:
            if row_index[1] < min_y:
                min_y = row_index[1]
            elif row_index[1] > max_y:
                max_y = row_index[1]

    return min_x, min_y, max_x, max_y


# If we ever would want to plot something..
def df_to_plot(df):
    plt.figure()
    plt.figure(figsize=(10, 10))
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=14)
    plt.xlabel('Component - 1', fontsize=20)
    plt.ylabel('Component - 2', fontsize=20)
    plt.title("Component Analysis Dataset", fontsize=20)
    targets = ['component 1', 'component 2']
    color = 'r'
    # indicesToKeep = df['label'] == target
    # indicesToKeep = target
    plt.scatter(df.loc[:, 'component 1']
                , df.loc[:, 'component 2'], c=color, s=50)

    plt.legend(targets, prop={'size': 15})
    plt.show()







