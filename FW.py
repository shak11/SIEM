import ML
import time
import pandas as pd
import consts as c


# Get the uniq rows based on ML high values
def get_uniq(origin, ml):
    rows = pd.DataFrame(columns=origin.columns)
    min_x, min_y, max_x, max_y = ML.get_min_max(ml)
    row_number = 0
    # Get current place
    for row_ml in ml.iterrows():
        values = row_ml[1]
        if (min_x > values[0] or values[0] > max_x) and (min_y > values[1] or values[1] > max_y):
            # Deprecated
            # rows = rows.append(origin.loc[row_ml[0]])
            rows.loc[row_number] = origin.iloc[row_ml[0]]
            row_number += 1
    return rows


if __name__ == "__main__":
    try:
        while True:
            features = [c.Beautify_FW_Parser[2], c.Beautify_FW_Parser[3], c.Beautify_FW_Parser[4], c.Beautify_FW_Parser[7]]
            original = ML.load_df("FW")
            df = ML.get_attacks(ML.load_df("FW"), features)
            line = get_uniq(original, df)

            # Remove duplicates
            line = line.drop_duplicates(keep='last', subset=[c.Beautify_FW_Parser[3], c.Beautify_FW_Parser[4],
                                                             c.Beautify_FW_Parser[5]])
            line.to_csv(c.ALERT_FILE_NAME, index=False)
            print(time.strftime("%H:%M:%S") + " ML Cycle Done!")
            time.sleep(c.Refresh_rate)

    except KeyboardInterrupt:
        print("Crtl+C Pressed. \r\nStopping ML!")

    # FIX 30min duration in web UI
