import subprocess, os
from flask import flash

class LogAnalysisModel:
    def __init__(self, pcap_directory, filename):
        self._pcap_directory = pcap_directory
        self._filename = filename

    def create_test_data(self):
        cic_flow_path = "/opt/app/CICFlowMeter-4.0/bin/"
        os.chdir(cic_flow_path)
        command = ['/opt/app/CICFlowMeter-4.0/bin/cfm', self._pcap_directory, "/opt/app/NetFlowInsight/log_analysis/data"]
        subprocess.run(command, check=True)
        result = self._run_model()
        return result

    
    def _run_model(self): 
        import numpy as np
        import pandas as pd
        from sklearn.linear_model import LogisticRegression
        from sklearn.tree import DecisionTreeClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler
        from sklearn.metrics import r2_score,mean_squared_error as mse
        from sklearn import metrics
        import joblib
        import pickle

        # Load the model, scaler, and PCA
        model = pickle.load(open('/opt/app/NetFlowInsight/log_analysis/model.pkl', 'rb'))
        scaler = pickle.load(open('/opt/app/NetFlowInsight/log_analysis/dec_tree_scaler.pkl', 'rb'))
        pca = pickle.load(open('/opt/app/NetFlowInsight/log_analysis/dec_tree_pca.pkl', 'rb'))

        data_filename = self._filename + "_Flow.csv"
        df = pd.read_csv(f'/opt/app/NetFlowInsight/log_analysis/data/{data_filename}', skipinitialspace=True, low_memory=False)

        drop_col = ["Flow ID", "Src IP", "Dst IP", "Timestamp", "Label"]
        df.drop(drop_col, axis=1, inplace=True)

        # Preprocessing test data
        df = df.replace("Infinity", 10000000)
        df = df.fillna(0)
        df = df.replace([np.inf, -np.inf], 0)

        # Scale and transform the test data using the loaded scaler
        X_test = scaler.transform(df)

        # Apply PCA transformation to the scaled test data
        X_test = pca.transform(X_test)

        y_pred = model.predict(X_test)

        predicted_counts = pd.Series(y_pred).replace([0,1],["Benign", "DOS/DDOS"]).value_counts()



        print(f"\nCount of predicted netflows: {predicted_counts.to_string()}")

        result_1 = f"\nCount of predicted netflows: \n{predicted_counts.to_string()}"

        probabilities = model.predict_proba(X_test)

        # The probability of the positive class (class 1)
        positive_class_probabilities = probabilities[:, 1]

        final_probability = (np.mean(positive_class_probabilities))*100

        result_2 = f"\n\nActual probability of the pcap having DOS/DDOS netflow:{final_probability: .2f}%"
        result = result_1 + result_2
        return result



