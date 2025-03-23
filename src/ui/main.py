import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

import numpy as np
import pandas as pd
import scipy.io.arff as arff
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns
from sklearn import metrics
from sklearn.decomposition import PCA
from sklearn.metrics import confusion_matrix, roc_curve, auc, ConfusionMatrixDisplay

from src.machine_learning.trainer import MLTrainer

ml_trainer = MLTrainer()
root = tk.Tk()
root.title("IDS Model Trainer")

# TODO: remove the default value
# TODO: provide option to download NSL-KDD dataset
dataset_path = tk.StringVar(
    value="C:/Users/Kosta/IdeaProjects/kddtest4/archive/KDDTrain+.arff"
)


def make_screen():
    # this creates a frame that is always positioned the same,
    # and can be brought to the foreground (switching to the screen)
    # via tkraise()
    frame = tk.Frame(root)
    frame.grid(row=0, column=0, sticky="news")
    return frame


def select_dataset():
    path = filedialog.askopenfilename()
    dataset_path.set(path)


select_dataset_screen = make_screen()
dataset_data = None
dataset_metadata = None
tk.Entry(select_dataset_screen, width=60, textvariable=dataset_path).pack()
tk.Button(
    select_dataset_screen, text="Select Dataset (ARFF)", command=select_dataset
).pack()


def load_dataset():
    global dataset_data, dataset_metadata
    if dataset_path.get().strip() == "":
        messagebox.showerror(
            "Missing Dataset",
            "You have not selected a dataset. Please click `Select Dataset`, then continue.",
        )
        return
    try:
        dataset_data, dataset_metadata = arff.loadarff(dataset_path.get())
    except Exception as e:
        messagebox.showerror(
            "Invalid Dataset", f"Dataset is not a valid ARFF file: {e}"
        )
        return
    update_features()
    select_features_screen.tkraise()
    if print_data_graphs.get():
        open_data_charts_window()


load_dataset_frame = tk.Frame(select_dataset_screen)
load_dataset_frame.pack()
tk.Button(load_dataset_frame, text="Load Dataset", command=load_dataset).grid(
    row=0, column=0
)
print_data_graphs = tk.BooleanVar(value=True)
tk.Checkbutton(
    load_dataset_frame, variable=print_data_graphs, text="Print data graphs?"
).grid(row=0, column=1)


def train_model():
    print("training")
    print(model_name)
    print(selected_features)
    print(dataset_path.get())
    ml_trainer.train(model_name.get(), selected_features, dataset_path.get())
    # call open_model_charts_window() with data from model after training
    # TODO: replace this with actual model predictions and y_test data
    predictions_mapped = [
        "normal",
        "normal",
        "normal",
        "attack",
        "attack",
        "attack",
        "attack",
        "attack",
    ]
    Y_test_mapped = [
        "attack",
        "normal",
        "normal",
        "normal",
        "attack",
        "normal",
        "normal",
        "attack",
    ]
    open_model_charts_window(predictions_mapped, Y_test_mapped)


model_name = tk.StringVar(value="gnb")

select_features_screen = make_screen()
tk.Button(
    select_features_screen,
    text="Go Back",
    command=lambda: select_dataset_screen.tkraise(),
).pack()
tk.Label(
    select_features_screen, text="Select the features you want to train with:"
).pack()
features_frame = tk.Frame(select_features_screen)
features_frame.pack()
tk.OptionMenu(select_features_screen, model_name, "random_forest", "gnb", "cnb").pack()
tk.Button(select_features_screen, text="Train Model", command=train_model).pack()

selected_features = []


def update_features():
    # update the list of features
    features_frame.children.clear()
    grid_columns = 4
    for index, field in enumerate(dataset_metadata.names()):
        var = tk.BooleanVar(value=True)

        def on_check(f=field, v=var):
            if v.get() and f not in selected_features:
                selected_features.append(f)
            elif not v.get() and f in selected_features:
                selected_features.remove(f)

        checkbutton = tk.Checkbutton(
            features_frame, text=field, variable=var, command=on_check
        )
        selected_features.append(field)
        checkbutton.grid(row=index // grid_columns, column=index % grid_columns)


def create_scrolled_tab(tab):
    scroll_container = tk.Frame(tab)
    create_save_close_bar(tab)
    scroll_container.pack(fill="both", expand=True)

    scroll_canvas = tk.Canvas(scroll_container)
    scroll_canvas.pack(side="left", fill="both", expand=True)

    scrollbar = ttk.Scrollbar(
        scroll_container, orient="vertical", command=scroll_canvas.yview
    )
    scrollbar.pack(side="right", fill="y")
    scroll_canvas.configure(yscrollcommand=scrollbar.set)

    plot_frame = tk.Frame(scroll_canvas)
    scroll_canvas.create_window((0, 0), window=plot_frame, anchor="nw")

    def on_frame_configure(event):
        scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all"))

    plot_frame.bind("<Configure>", on_frame_configure)

    return plot_frame


def open_model_charts_window(predictions_mapped, Y_test_mapped):
    new_window = tk.Toplevel(root)
    new_window.title("Model Charts")
    notebook = ttk.Notebook(new_window)
    notebook.pack(fill="both", expand=True)

    # scores
    Accuracy = metrics.accuracy_score(Y_test_mapped, predictions_mapped)
    Sensitivity = metrics.recall_score(
        Y_test_mapped, predictions_mapped, pos_label="attack"
    )
    Precision = metrics.precision_score(
        Y_test_mapped, predictions_mapped, pos_label="attack"
    )
    F1_score = metrics.f1_score(Y_test_mapped, predictions_mapped, pos_label="attack")
    Recall = metrics.recall_score(Y_test_mapped, predictions_mapped, pos_label="attack")

    tab = ttk.Frame(notebook)
    tk.Label(tab, text=f"Accuracy: {Accuracy:.7f}").pack()
    tk.Label(tab, text=f"Sensitivity: {Sensitivity:.7f}").pack()
    tk.Label(tab, text=f"Precision: {Precision:.7f}").pack()
    tk.Label(tab, text=f"F1 Score: {F1_score:.7f}").pack()
    tk.Label(tab, text=f"Recall: {Recall:.7f}").pack()
    notebook.add(tab, text=f"Confusion Matrix")

    # confusion matrix
    Confusion_Matrix = metrics.confusion_matrix(Y_test_mapped, predictions_mapped)
    disp = ConfusionMatrixDisplay(
        confusion_matrix=Confusion_Matrix, display_labels=["Normal", "Attack"]
    )
    fig, ax = plt.subplots(figsize=(5.5, 5))
    disp.plot(cmap="Blues", ax=ax)

    tab = ttk.Frame(notebook)
    create_tab_with_fig(tab, fig, ax, notebook, "Confusion Matrix")

    # ROC curve
    fpr, tpr, _ = roc_curve(
        [1 if y == "attack" else 0 for y in Y_test_mapped],
        [1 if y == "attack" else 0 for y in predictions_mapped],
    )
    roc_auc = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, label=f"ROC curve (area = {roc_auc:.2f})", color="blue")
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve")
    ax.legend()

    tab = ttk.Frame(notebook)
    create_tab_with_fig(tab, fig, ax, notebook, "ROC Curve")


def open_data_charts_window():
    new_window = tk.Toplevel(root)
    new_window.title("Data Charts")
    notebook = ttk.Notebook(new_window)
    notebook.pack(fill="both", expand=True)

    # print correlation matrix
    df = pd.DataFrame(dataset_data, columns=dataset_metadata.names())
    data_cleaned = df.dropna(axis="columns")

    ndf = data_cleaned[
        [
            col
            for i, col in enumerate(dataset_metadata.names())
            if dataset_metadata.types()[i] == "numeric"
            and data_cleaned[col].nunique() > 1
        ]
    ]
    corr = ndf.corr()

    fig, ax = plt.subplots(figsize=(6, 5.5))
    sns.heatmap(corr, ax=ax)
    ax.set_title("Correlation Matrix")
    fig.tight_layout()

    tab = ttk.Frame(notebook)
    create_tab_with_fig(tab, fig, ax, notebook, "Correlation Matrix")

    # normal vs attack traffic
    attack_counts = data_cleaned["class"].value_counts()

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(attack_counts.index, attack_counts.values, color=["green", "red"])
    ax.set_title("Attack vs Normal Traffic")
    ax.set_ylabel("Count")

    tab = ttk.Frame(notebook)
    create_tab_with_fig(tab, fig, ax, notebook, "Attack vs Normal Traffic")

    # PCA graph
    num_features = data_cleaned.select_dtypes(include=["number"]).columns
    X_pca = PCA(n_components=2).fit_transform(data_cleaned[num_features])

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.scatter(
        X_pca[:, 0],
        X_pca[:, 1],
        alpha=0.5,
        marker="o",
        c=["red" if x == "attack" else "blue" for x in data_cleaned["class"]],
    )
    ax.set_title("PCA Projection of Features")

    tab = ttk.Frame(notebook)
    create_tab_with_fig(tab, fig, ax, notebook, "PCA graph")

    # histograms of numeric features
    tab = ttk.Frame(notebook)
    plot_frame = create_scrolled_tab(tab)

    for feature in num_features:
        if data_cleaned[feature].nunique() <= 2:
            fig, ax = plt.subplots(figsize=(6, 4))
            value_counts = data_cleaned[feature].value_counts()
            ax.bar(value_counts.index.astype(str), value_counts.values)
            ax.set_yscale("log")
            ax.set_title(f"{feature} (Numeric, normal scale of X and log scale of Y)")
            canvas = FigureCanvasTkAgg(fig, master=plot_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
        else:
            fig, ax = plt.subplots(figsize=(6, 4))
            shifted_values = data_cleaned[feature].apply(
                lambda val: val + 1 if val <= 0 else val
            )
            min_val = shifted_values.min()
            max_val = shifted_values.max()
            bin_count = 8
            bin_edges = np.geomspace(min_val, max_val, bin_count)
            ax.hist(shifted_values, bins=bin_edges, edgecolor="black")
            ax.set_yscale("log")
            ax.set_xscale("log")
            ax.set_xticks(bin_edges)
            ax.set_xticklabels([f"{edge:.2g}" for edge in bin_edges])
            ax.set_title(f"{feature} (Numeric, log scale of X and Y)")
            ax.tick_params(axis="x", rotation=90)

            canvas = FigureCanvasTkAgg(fig, master=plot_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
    notebook.add(tab, text=f"numeric features")
    # histograms of categorical features
    tab = ttk.Frame(notebook)
    plot_frame = create_scrolled_tab(tab)

    cat_features = data_cleaned.select_dtypes(include=["object"]).columns
    for feature in cat_features:
        value_counts = data_cleaned[feature].value_counts()
        fig, ax = plt.subplots(figsize=(max(value_counts.size / 6, 6), 4))
        ax.bar(value_counts.index.astype(str), value_counts.values)
        ax.set_yscale("log")
        ax.tick_params(axis="x", rotation=90)
        ax.set_title(f"{feature} (Categorical, normal scale of X and log scale of Y)")
        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=plot_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(expand=True)

    notebook.add(tab, text=f"categorical features")


def create_save_close_bar(diagram_frame, fig=None, title="fig"):
    button_frame = tk.Frame(diagram_frame)
    button_frame.pack(anchor="n", fill="x")
    button_frame.columnconfigure(0, weight=1)  # Platz zwischen den Buttons
    button_frame.columnconfigure(1, weight=0)
    close_button = tk.Button(
        button_frame, text="X", fg="red", command=diagram_frame.destroy, bd=0
    )
    close_button.grid(row=0, column=1, padx=1, sticky="e")
    if fig is None:
        return
    save_button = tk.Button(
        button_frame, text="💾", fg="blue", command=lambda: save_fig(fig, title), bd=0
    )
    save_button.grid(row=0, column=0, padx=1, sticky="w")


def save_fig(fig, title):
    file_path = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG files", "*.png"), ("All Files", "*.*")],
        initialfile=f"{title}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png",
    )
    if file_path:
        fig.savefig(file_path)
        messagebox.showinfo("Saved", f"Fig saved as {file_path}")


def create_tab_with_fig(tab, fig, ax, notebook, title):
    create_save_close_bar(tab, fig, ax.get_title())
    canvas = FigureCanvasTkAgg(fig, master=tab)
    canvas.draw()
    canvas.get_tk_widget().pack(expand=True)
    notebook.add(tab, text=title)


analysis_screen = make_screen()
tk.Button(
    analysis_screen, text="Go Back", command=lambda: select_features_screen.tkraise()
).pack()
fig, ax0 = plt.subplots()
canvas = FigureCanvasTkAgg(figure=fig, master=analysis_screen)
canvas.draw()
canvas.get_tk_widget().pack()

select_dataset_screen.tkraise()
root.mainloop()
