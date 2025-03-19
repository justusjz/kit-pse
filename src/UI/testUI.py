import tkinter as tk
from tkinter import ttk, messagebox, Canvas, Scrollbar, Frame, filedialog
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
import numpy as np
import pandas as pd
from datetime import datetime

# NSL-KDD Dataset laden
def load_nsl_kdd():
    column_names = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "class", "level"]

    data = pd.read_csv("nsl-kdd/KDDTrain+.txt", names=column_names, index_col=False)
    data_test = pd.read_csv("nsl-kdd/KDDTest+.txt", names=column_names, index_col=False)

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

# Globale Variablen für das Modell und die Daten
predictions: dict = {}
Y_test = None

# Modell Training
def train_model():
    global predictions, Y_test
    model_name = model_var.get()
    if not model_name:
        messagebox.showwarning("Warning", "Please select a model")
        return

    X_train, Y_train, X_test, Y_test = load_nsl_kdd()

    models = {
        "Random Forest": RandomForestClassifier(n_estimators=30),
        "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=15, weights="distance"),
        "Naive Bayes": GaussianNB(),
        "Decision Tree": DecisionTreeClassifier(),
        "Logistic Regression": LogisticRegression()
    }

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

def save_heatmap(fig):

    file_path = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG files", "*.png"), ("All Files", "*.*")],
        initialfile=f"heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    )
    if file_path:
        fig.savefig(file_path)
        messagebox.showinfo("Saved", f"Heatmap saved as {file_path}")



def generate_histogram():
    global canvas

    # Beispiel-Histogrammdaten
    data = np.random.exponential(scale=2.0, size=1000)

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.hist(data, bins=20, edgecolor="black")
    ax.set_xscale("log")
    ax.set_title("Logarithmic Histogram")

    canvas = FigureCanvasTkAgg(fig, master=frame_chart)
    canvas.draw()
    canvas.get_tk_widget().pack()

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
models = ["Random Forest", "K-Nearest Neighbors", "Naive Bayes", "Decision Tree", "Logistic Regression"]

dropdown = ttk.Combobox(root, textvariable=model_var, values=models)
dropdown.pack(pady=10)
model_var.trace_add("write", update_label_selected_model_accuracy)

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

# btn_histogram = tk.Button(frame_buttons, text="Generate Histogram", command=generate_histogram)
# btn_histogram.grid(row=0, column=1, padx=5)

# Frame für die Diagramme
frame_chart = tk.Frame(root)
frame_chart.pack(fill=tk.BOTH, expand=True)

# Hauptloop starten
root.mainloop()
