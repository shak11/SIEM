from sklearn.decomposition import PCA
import plotly.express as px
import plotly.io as pio
from os import path
import pandas as pd
import numpy as np
import re

# Set machine learning here


# Junk / NOT WORKING properly
def load_log(log_string_list):

    pattern = re.compile('(\w+)=(?:"([^"]*)"|(\S*))')
    lines_s = pd.Series(log_string_list)
    data = lines_s.str.extractall(pattern)
    data.index = data.index.get_level_values(0)
    data[1] = data[1].fillna(data[2])
    return data.pivot(index=None, columns=0, values=1)

# Junkkkk / NOT NEEDED
def process_file(file):

    output_folder = r"C:\logs_vpn_out"
    first = True
    log_df = []
    with open(file, "r") as f:
        if first:
            log_df = load_log(f.readlines())
            first = False
        else:
            t_df = load_log(f.readlines())
            log_df = log_df.append(t_df)
            del t_df
    file_name = path.basename(file)
    file_path = output_folder + "\\" + file_name + ".csv"
    log_df.to_csv(file_path)

    del log_df



pio.renderers.default = 'iframe'
fig = px.bar(df_ext_10.iloc[2:8], y="remip", x="sentbyte", title='Destiantion IPs by data sent', orientation='h')
fig.show()


def apply_pca2(df_int):

    df_int.replace(np.nan, "-", inplace=True)

    pca = PCA(n_components=2)
    principalComponents = pca.fit_transform(df_int)

    principalDf = pd.DataFrame(data=principalComponents, columns=['x', 'y'])

    return principalDf


# Insert here all the data
df_work = load_log()
df_final = df_work.remip.unique()
df_final = pd.Series(df_final).to_frame().rename(columns={0:"remip"})
duration_t = df_work[["remip", "duration", "tunnelid"]].groupby(["remip", "tunnelid"]).max().dropna().reset_index()

df_final["n_tunnels"] = df_final["remip"].map(duration_t[["remip", "duration"]].groupby("remip").count()["duration"])
df_final["n_connections"] = df_final["remip"].map(df_work.value_counts("remip"))
df_final["duration_sum"] = df_final["remip"].map(duration_t[["remip", "duration"]].groupby("remip").sum()["duration"])

sentby_t = df_work[~df_work["tunnelid"].isnull()][["remip", "sentbyte", "tunnelid"]].groupby(["remip", "tunnelid"]).max().dropna().reset_index()
df_final["sentbyte_sum"] = df_final["remip"].map(sentby_t[["remip", "sentbyte"]].groupby("remip").sum()["sentbyte"])
df_final = df_final[~df_final["n_tunnels"].isnull()]

df_pca = df_final[["n_tunnels", "n_connections", "duration_sum", "sentbyte_sum"]]
df_pca_final = apply_pca2(df_pca)

remip = df_final["remip"].reset_index()
dfjoin = df_pca_final.join(remip)