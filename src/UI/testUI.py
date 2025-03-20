import tkinter as tk
from tkinter import ttk, messagebox, Canvas, Scrollbar, Frame, filedialog
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sklearn import metrics
from sklearn.compose import ColumnTransformer
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
import numpy as np
import pandas as pd
from datetime import datetime
import tkinter as tk
from tkinter import ttk
import json
import requests

# Globale Variablen für das Modell und die Daten
predictions: dict = {}
Y_test = None
data = None

gnb = GaussianNB()
knn = KNeighborsClassifier(n_neighbors=15, weights="distance")

models = {
    "Random Forest": RandomForestClassifier(n_estimators=30),
    "K-Nearest Neighbors": knn,
    "Naive Bayes": gnb,
    "Decision Tree": DecisionTreeClassifier(),
    "Logistic Regression": LogisticRegression(),
    "MLP": MLPClassifier(),
    "Voting classifier": VotingClassifier(estimators=[
        ('Naive Bayes', gnb),
        ('knn', knn)
    ], voting='soft'),
    "SGD Classifier" : SGDClassifier()
}

column_names = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "class", "level"]



# NSL-KDD Dataset laden
def load_nsl_kdd():
    global data


    TRAIN_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain+.txt"  # url for the training set
    TEST_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest+.txt"    # url for the test set
    data = pd.read_csv(TRAIN_URL, names=column_names, index_col=False)
    data_test = pd.read_csv(TEST_URL, names=column_names, index_col=False)

    categorical_features = ["protocol_type", "service", "flag"]
    numerical_features = list(set(column_names) - set(categorical_features) - {"class"} - {"level"})

    preprocessor_X = ColumnTransformer([
        ("cat", OneHotEncoder(), categorical_features),
        ("num", MinMaxScaler(), numerical_features)
    ])

    X_train = preprocessor_X.fit_transform(data.drop(columns=["class", "level"]))
    #Y_train = data["class"].apply(lambda x: "normal" if x == "normal" else "attack")
    Y_train = data["class"]

    X_test = preprocessor_X.transform(data_test.drop(columns=["class", "level"]))
    #Y_test = data_test["class"].apply(lambda x: "normal" if x == "normal" else "attack")
    Y_test = data_test["class"]

    return X_train, Y_train, X_test, Y_test

# Modell Training
def train_model():
    global predictions, Y_test
    model_name = model_var.get()
    if not model_name:
        messagebox.showwarning("Warning", "Please select a model")
        return

    X_train, Y_train, X_test, Y_test = load_nsl_kdd()

    model = models[model_name]
    model.fit(X_train, Y_train)
    predictions[model_name] = model.predict(X_test)
    accuracy = accuracy_score(Y_test, predictions[model_name])

    selected_text = f"previous accuracy: {accuracy:.4f}"
    label_selected_model_accuracy.config(text=selected_text)

    messagebox.showinfo("Model Accuracy", f"{model_name} Accuracy: {accuracy:.4f}")

def generate_heatmap():
    global predictions, Y_test

    model_name = model_var.get()

    if model_name is None or model_name not in predictions.keys() or Y_test is None:
        messagebox.showwarning("Warning", "Train a model first!")
        return


    predictions_mapped = ["normal" if pred == "normal" else "attack" for pred in predictions[model_name]]
    Y_test_mapped = ["normal" if y == "normal" else "attack" for y in Y_test]

    cm = confusion_matrix(Y_test_mapped, predictions_mapped, labels=["normal", "attack"])

    # heatmap_window = tk.Toplevel(root)
    # heatmap_window.title("Confusion Matrix")
    # heatmap_window.geometry("600x500")

    heatmap_frame = tk.Frame(scrollable_frame, bd=2, relief="ridge")
    heatmap_frame.pack(pady=5, padx=5, fill="x")

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, cmap="Blues", xticklabels=["normal", "attack"], yticklabels=["normal", "attack"], ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix for %s" % model_name)

    Confusion_Matrix = metrics.confusion_matrix(Y_test_mapped, predictions_mapped)
    disp = ConfusionMatrixDisplay(confusion_matrix=Confusion_Matrix, display_labels=['Normal', 'Attack'])
    fig, ax = plt.subplots(figsize=(5.55, 5))
    disp.plot(cmap='Blues', ax=ax)

    fpr, tpr, _ = roc_curve([1 if y == "attack" else 0 for y in Y_test_mapped], [1 if y == "attack" else 0 for y in predictions_mapped])
    roc_auc = auc(fpr, tpr)


    fig_roc, ax_roc = plt.subplots(figsize=(6, 5))
    ax_roc.plot(fpr, tpr, label=f"ROC curve (area = {roc_auc:.2f})", color="blue")
    ax_roc.plot([0, 1], [0, 1], linestyle="--", color="gray")
    ax_roc.set_xlabel("False Positive Rate")
    ax_roc.set_ylabel("True Positive Rate")
    ax_roc.set_title("ROC Curve")
    ax_roc.legend()

    # feature_importances = models[model_name].feature_importances_
    # features = column_names
    #
    # # Sortieren und plotten
    # indices = np.argsort(feature_importances)[::-1]
    #
    # fig_important, ax_important = plt.subplots(figsize=(8, 5))
    # ax_important.bar(range(len(features)), feature_importances[indices], align="center")
    # ax_important.set_xticks(range(len(features)), np.array(features)[indices], rotation=90)
    # ax_important.set_xlabel("Feature")
    # ax_important.set_ylabel("Importance Score")
    # ax_important.set_title("Feature Importances")



    # canvas = FigureCanvasTkAgg(fig, master=heatmap_window)
    # canvas.draw()
    # canvas.get_tk_widget().pack()
    #
    # heatmap_windows.append(heatmap_window)

    button_frame = tk.Frame(heatmap_frame)
    button_frame.pack(anchor="n", fill="x")
    button_frame.columnconfigure(0, weight=1)  # Platz zwischen den Buttons
    button_frame.columnconfigure(1, weight=0)
    close_button = tk.Button(button_frame, text="X", fg="red", command=heatmap_frame.destroy, bd=0)
    close_button.grid(row=0, column=1, padx=1, sticky="e")
    save_button = tk.Button(button_frame, text="💾", fg="blue", command=lambda:save_heatmap(fig), bd=0)
    save_button.grid(row=0, column=0, padx=1, sticky="w")

    canvas = FigureCanvasTkAgg(fig, master=heatmap_frame)
    canvas.draw()
    canvas.get_tk_widget().pack()

    canvas2 = FigureCanvasTkAgg(fig_roc, master=heatmap_frame)
    canvas2.draw()
    canvas2.get_tk_widget().pack()

def save_heatmap(fig):

    file_path = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG files", "*.png"), ("All Files", "*.*")],
        initialfile=f"heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    )
    if file_path:
        fig.savefig(file_path)
        messagebox.showinfo("Saved", f"Heatmap saved as {file_path}")



def generate_data_analysis():
    load_nsl_kdd()
    global data

    analysis_window = tk.Toplevel(root)
    analysis_window.title("Data Analysis")
    analysis_window.geometry("1280x920")

    # Erstelle zwei Frames für die linke und rechte Hälfte
    bottom_frame = tk.Frame(analysis_window, width=1280, height=460)
    top_frame = tk.Frame(analysis_window, width=1280, height=460)

    # Packe die Frames in das Fenster
    bottom_frame.grid(row=1, column=0, sticky="nsew")
    top_frame.grid(row=0, column=0, sticky="nsew")

    # Stelle sicher, dass sich das Grid anpasst
    analysis_window.grid_columnconfigure(0, weight=1)
    analysis_window.grid_columnconfigure(1, weight=1)
    analysis_window.grid_rowconfigure(0, weight=1)

    ddata = np.array(data["src_bytes"])  # Sicherstellen, dass es ein NumPy-Array ist
    min_val = np.min(ddata[ddata > 0])  # Kleinster Wert > 0
    max_val = np.max(ddata)  # Größter Wert
    bins = np.geomspace(min_val, max_val, 10)
    bins = np.insert(bins, 0, 0)

    fig, ax = plt.subplots(figsize=(4, 4))
    ax.hist(data["src_bytes"], bins=bins, edgecolor="black")
    ax.set_xscale("log")
    ax.set_title("Histogram of src_bytes")

    canvas = FigureCanvasTkAgg(fig, master=top_frame)
    canvas.draw()
    canvas.get_tk_widget().grid(row=0, column=0, padx=1, pady=1)

    data_cleaned = data.dropna(axis="columns")
    ndf = data_cleaned[[col for col in data_cleaned.columns if data_cleaned[col].nunique() > 1 and pd.api.types.is_numeric_dtype(data_cleaned[col])]]
    corr = ndf.corr()

    fig2, ax2 = plt.subplots(figsize=(4, 4))
    sns.heatmap(corr, ax=ax2)
    ax2.set_title("Correlation Matrix")

    canvas2 = FigureCanvasTkAgg(fig2, master=top_frame)
    canvas2.draw()
    canvas2.get_tk_widget().grid(row=0, column=1, padx=1, pady=1)

    #categorical_features = ["protocol_type", "service", "flag"]
    chosen_features = [c for c in choices if globals()["var_" + c].get()]
    for feature in chosen_features:
        if pd.api.types.is_numeric_dtype(data_cleaned[feature]):
            fig3, ax = plt.subplots(figsize=(6, 4), dpi=100)
            shifted_values = data_cleaned[feature].apply(lambda val: val+1 if val<=0 else val)
            min_val = shifted_values.min()
            max_val = shifted_values.max()
            bin_count = 8
            bin_edges = np.geomspace(min_val, max_val, bin_count)
            ax.hist(shifted_values, bins=bin_edges, edgecolor="black")
            ax.set_yscale("log")
            ax.set_xscale("log")
            ax.set_xticks(bin_edges)
            ax.set_xticklabels([f"{edge:.2g}" for edge in bin_edges])
            ax.set_title(f"{feature} (Numeric, log scale of Y)")
            ax.tick_params(axis='x', rotation=90)
        else:
            category_counts = data_cleaned[feature].value_counts()
            fig3, ax = plt.subplots(figsize=(6, 4), dpi=100)
            ax.bar(category_counts.index, category_counts.values)
            ax.set_title(f"{feature} (Categorical)")
            ax.tick_params(axis='x', rotation=90)

        cat_window = tk.Toplevel(analysis_window)
        cat_window.title(f"Data: {feature}")
        canvas3 = FigureCanvasTkAgg(fig3, master=cat_window)
        canvas3.draw()
        canvas3.get_tk_widget().pack(fill="both", expand=True)

    # canvas3 = FigureCanvasTkAgg(fig3, master=bottom_frame)
    # canvas3.draw()
    # canvas3.get_tk_widget().pack(anchor="se", fill="x")

    attack_types = data_cleaned["class"].apply(lambda x: "normal" if x == "normal" else "attack")
    attack_counts = attack_types.value_counts()

    fig4, ax4 = plt.subplots(figsize=(4, 4))
    ax4.bar(attack_counts.index, attack_counts.values, color=['green', 'red'])
    ax4.set_title("Attack vs Normal Traffic")
    ax4.set_ylabel("Count")

    canvas4 = FigureCanvasTkAgg(fig4, master=top_frame)
    canvas4.draw()
    canvas4.get_tk_widget().grid(row=0, column=2, padx=1, pady=1)

    num_features = data_cleaned.select_dtypes(include=["number"]).columns
    X_pca = PCA(n_components=2).fit_transform(data_cleaned[num_features])

    fig6, ax6 = plt.subplots(figsize=(4, 4))
    ax6.scatter(X_pca[:, 0], X_pca[:, 1], alpha=0.5, marker="o", c=["red" if x == "attack" else "blue" for x in attack_types])
    ax6.set_title("PCA Projection of Features")

    canvas6 = FigureCanvasTkAgg(fig6, master=top_frame)
    canvas6.draw()
    canvas6.get_tk_widget().grid(row=0, column=3, padx=1, pady=1)


# Funktion zur Aktualisierung des Labels
def update_label_selected_model_accuracy(*args):
    if model_var.get() in predictions.keys():
        selected_text = f"previous accuracy: {accuracy_score(Y_test, predictions[model_var.get()]):.4f}"
        label_selected_model_accuracy.config(text=selected_text)
    else:
        label_selected_model_accuracy.config(text="")

# Tkinter Fenster erstellen
root = tk.Tk()
root.title("ML Model Trainer")
root.geometry("1000x600")

# Frame für Heatmaps mit Scrollfunktion
frame_container = Frame(root)
frame_container.pack(side="left", fill="both", expand=True, padx=10, pady=10)

canvas = Canvas(frame_container)
scrollbar = Scrollbar(frame_container, orient="vertical", command=canvas.yview)
scrollable_frame = Frame(canvas)

scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(
        scrollregion=canvas.bbox("all")
    )
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# Dropdown-Menü zur Auswahl des ML-Modells
model_var = tk.StringVar()
#models = ["Random Forest", "K-Nearest Neighbors", "Naive Bayes", "Decision Tree", "Logistic Regression"]

dropdown = ttk.Combobox(root, textvariable=model_var, values=list(models.keys()))
dropdown.pack(pady=10)
model_var.trace_add("write", update_label_selected_model_accuracy)

# Dropdown\-Menü zur Auswahl der zu analysierenden Sachen
choice = tk.StringVar()
checkbox_frame = tk.Frame(root)
checkbox_frame.pack(fill="both", expand=True)

checkbox_canvas = tk.Canvas(checkbox_frame)
checkbox_canvas.pack(side="left", fill="both", expand=True)

scrollbar_checkboxes = tk.Scrollbar(checkbox_frame, orient="vertical", command=checkbox_canvas.yview)
scrollbar_checkboxes.pack(side="right", fill="y")

checklist_frame = tk.Frame(checkbox_canvas)
checklist_frame.bind("<Configure>", lambda e: checkbox_canvas.configure(scrollregion=checkbox_canvas.bbox("all")))
checkbox_canvas.create_window((0,0), window=checklist_frame, anchor="nw", tags="checklist_frame")
checkbox_canvas.configure(yscrollcommand=scrollbar_checkboxes.set)

choices = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "class", "level"]
for c in choices:
    globals()["var_" + c] = tk.BooleanVar()
    checkbox = tk.Checkbutton(checklist_frame, text=c, variable=globals()["var_" + c])
    checkbox.pack(anchor="w")

label_selected_model_accuracy = tk.Label(root, text="", font=("Arial", 10))
label_selected_model_accuracy.pack()

label_selected_model = tk.Label(root, text="Select a Model", font=("Arial", 12))
label_selected_model.pack()

# Train Button
btn_train = tk.Button(root, text="Train Model", command=train_model)
btn_train.pack(pady=10)

# Buttons zum Erstellen der Diagramme
frame_buttons = tk.Frame(root)
frame_buttons.pack(pady=10)

btn_heatmap = tk.Button(frame_buttons, text="Generate Heatmap", command=generate_heatmap)
btn_heatmap.grid(row=0, column=0, padx=5)

btn_histogram = tk.Button(frame_buttons, text="Generate Dataset analysis diagramms", command=generate_data_analysis)
btn_histogram.grid(row=0, column=1, padx=5)

btn_test = ttk.Button(frame_buttons, text="test", command="")
btn_test.grid(row=1, column=1, padx=5)

# Frame für die Diagramme
frame_chart = tk.Frame(root)
frame_chart.pack(fill=tk.BOTH, expand=True)

# Hauptloop starten
root.mainloop()
