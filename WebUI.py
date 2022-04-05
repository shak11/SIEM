#!/usr/bin/env python
from flask import Flask, render_template, send_from_directory
import jinja2.exceptions
import pandas as pd
import consts as c
import datetime


def read_file(which):
    if which == c.WIN_FILE_NAME:
        df = pd.read_csv(c.WIN_FILE_NAME)
        df[c.Syslog_Windows_Parser[0]] = pd.to_datetime(df[c.Syslog_Windows_Parser[0]], infer_datetime_format=True)
    elif which == c.FW_FILE_NAME:
        df = pd.read_csv(c.FW_FILE_NAME)
        df[c.Beautify_FW_Parser[0]] = pd.to_datetime(df[c.Beautify_FW_Parser[0]], infer_datetime_format=True)
    if type(df) is not None:
        start_date = str(datetime.date.today() - datetime.timedelta(days=c.Days_Back))
        start_date = str(datetime.date.today() - datetime.timedelta(days=c.Days_Back))
        end_date = str(datetime.date.today())  # strftime("%d-%m-%y", gmtime())
        mask = (df[c.Syslog_Windows_Parser[0]] > start_date) & (df[c.Syslog_Windows_Parser[0]] <= end_date)
        df = df.loc[mask]
        return df, start_date, end_date


def Top_10_Windows_Event_List():
    df, start_date, end_date = read_file(c.WIN_FILE_NAME)
    top_10_win_event = df.groupby([c.Syslog_Windows_Parser[4], c.Syslog_Windows_Parser[5],
                                   c.Syslog_Windows_Parser[6]]).Event_ID.value_counts().nlargest(10)
    top_10_win_event = top_10_win_event.to_dict()
    top_10_win_event_list = []
    index = 1
    for key, value in top_10_win_event.items():
        top_10_win_event_list.append([index, int(key[0]), key[1], key[2], value])
        index += 1
    return top_10_win_event_list


def Top_10_FireWall_Event_List():
    df, start_date, end_date = read_file(c.FW_FILE_NAME)
    top_10_fw_event = df.groupby(
        [c.Beautify_FW_Parser[2], c.Beautify_FW_Parser[3], c.Beautify_FW_Parser[4], c.Beautify_FW_Parser[6],
         c.Beautify_FW_Parser[5], c.Beautify_FW_Parser[9]]).Dest_IP.value_counts().nlargest(10)
    top_10_fw_event = top_10_fw_event.to_dict()
    top_10_fw_event_list = []
    index = 1
    for key, value in top_10_fw_event.items():
        top_10_fw_event_list.append([index, key[0], key[1], key[2], key[3], key[4], key[5]])
        index += 1
    return top_10_fw_event_list


def Windows_Event_Summarty_Morris_Area_Data():
    df = pd.read_csv(c.WIN_FILE_NAME)
    df[c.Syslog_Windows_Parser[0]] = pd.to_datetime(df[c.Syslog_Windows_Parser[0]], infer_datetime_format=True)
    morris_area_data = []
    for i in range(0, 7):
        current_date = str(datetime.date.today() - datetime.timedelta(days=i))
        temp_df = df.loc[(df[c.Syslog_Windows_Parser[0]] == current_date)]
        temp = dict(temp_df[c.Syslog_Windows_Parser[5]].value_counts())
        # ERROR
        morris_area_data.append([str(current_date), int(temp.get("Critical", 0)), int(temp.get("Low", 0))])
    return morris_area_data


def Inbound_VS_Outbound_Summary_Traffic_Morris_Bar_Data():
    df = pd.read_csv(c.FW_FILE_NAME)
    df[c.Beautify_FW_Parser[0]] = pd.to_datetime(df[c.Beautify_FW_Parser[0]], infer_datetime_format=True)
    morris_bar_data = []
    for i in range(0, 7):
        current_date = str(datetime.date.today() - datetime.timedelta(days=i))
        temp_df = df.loc[(df[c.Beautify_FW_Parser[0]] == current_date)]
        Sent_Bytes = int(temp_df[c.Beautify_FW_Parser[10]].sum())
        Received_Bytes = int(temp_df[c.Beautify_FW_Parser[11]].sum())
        morris_bar_data.append([str(current_date), Sent_Bytes, Received_Bytes])
    return morris_bar_data


def Windows_Live_Attack():
    df = pd.read_csv(c.WIN_FILE_NAME)
    df[c.Syslog_Windows_Parser[0]] = pd.to_datetime(df[c.Syslog_Windows_Parser[0]], infer_datetime_format=True)
    current_time_minus_30min = datetime.datetime.today() - datetime.timedelta(hours=0, minutes=30)
    current_time_minus_30min = str(current_time_minus_30min.strftime('%H:%M:%S'))
    current_date = datetime.date.today()
    current_date = str(current_date.strftime('%d/%m/%Y'))
    mask = (df[c.Syslog_Windows_Parser[0]].dt.strftime('%d/%m/%Y') == current_date) & (df[c.Syslog_Windows_Parser[1]] >=
                                                                                       current_time_minus_30min)
    df = df.loc[mask]
    df = df[df[c.Syslog_Windows_Parser[5]] == "Critical"]
    df = df.sort_values(by=c.Syslog_Windows_Parser[1], ascending=False)
    df[c.Syslog_Windows_Parser[0]] = str((df[c.Syslog_Windows_Parser[0]]))
    Windows_Live_Attack_data = (df[[c.Syslog_Windows_Parser[1], c.Syslog_Windows_Parser[2], c.Syslog_Windows_Parser[4],
                                    c.Syslog_Windows_Parser[6]]].values.tolist())
    return Windows_Live_Attack_data


def Firewall_Live_Attack():

    df = pd.read_csv(c.ALERT_FILE_NAME)
    df[c.Beautify_FW_Parser[0]] = pd.to_datetime(df[c.Beautify_FW_Parser[0]], infer_datetime_format=True)
    print(df)

    current_time_minus_30min = datetime.datetime.today() - datetime.timedelta(hours=0, minutes=30)
    current_time_minus_30min = str(current_time_minus_30min.strftime('%H:%M:%S'))
    current_date = datetime.date.today()
    current_date = str(current_date.strftime('%Y-%d-%m'))

    mask = (df[c.Beautify_FW_Parser[0]].dt.strftime('%Y-%m-%d') == current_date) & (df[c.Beautify_FW_Parser[1]] >=
                                                                                    current_time_minus_30min)
    df = df.loc[mask]

    df = df.sort_values(by=c.Beautify_FW_Parser[1], ascending=False)
    df[c.Beautify_FW_Parser[0]] = str((df[c.Beautify_FW_Parser[0]]))
    Firewall_Live_Attack_data = (df[[c.Beautify_FW_Parser[1], c.Beautify_FW_Parser[3], c.Beautify_FW_Parser[4],
                                    c.Beautify_FW_Parser[5], c.Beautify_FW_Parser[6], c.Beautify_FW_Parser[9]]].values
                                 .tolist())
    return Firewall_Live_Attack_data

# app = Flask(__name__)
app = Flask("SIEM")


@app.route('/')
def index():
    top_10_win_event_list = Top_10_Windows_Event_List()
    top_10_fw_event_list = Top_10_FireWall_Event_List()
    morris_area_data = Windows_Event_Summarty_Morris_Area_Data()
    morris_bar_data = Inbound_VS_Outbound_Summary_Traffic_Morris_Bar_Data()
    Windows_Live_Attack_data = Windows_Live_Attack()
    Firewall_Live_Attack_data = Firewall_Live_Attack()

    return render_template(c.Web_UI, top_10_win_event=top_10_win_event_list,
                           top_10_fw_event_list=top_10_fw_event_list, morris_area_data=morris_area_data,
                           morris_bar_data=morris_bar_data, Windows_Live_Attack_data=Windows_Live_Attack_data,
                           Firewall_Live_Attack_data=Firewall_Live_Attack_data)


@app.route('/<path:resource>')
def serveStaticResource(resource):
    return send_from_directory('static/', resource)



@app.errorhandler(jinja2.exceptions.TemplateNotFound)
def template_not_found(e):
    print(e)
    return not_found(e)


@app.errorhandler(404)
def not_found(e):
    return '<strong>Page Not Found!</strong>', 404


if __name__ == '__main__':
    app.run()
