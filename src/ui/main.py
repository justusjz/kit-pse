import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

import numpy as np
import pandas as pd
import scipy.io.arff as arff
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns
from sklearn import metrics
from sklearn.decomposition import PCA
from sklearn.metrics import confusion_matrix, roc_curve, auc, ConfusionMatrixDisplay

from conf import BASE_DIR
from src.machine_learning.trainer import MLTrainer

# Initialize MLTrainer and Tkinter with ttkbootstrap
ml_trainer = MLTrainer()
root = ttk.Window(themename="superhero")  # Apply the superhero theme
root.title("IDS Model Trainer")
root.geometry("2000x700")
root.grid_columnconfigure(0, weight=1)  # Make the column expandable
root.grid_rowconfigure(0, weight=1)  # Make the row expandable
# TODO: provide option to download NSL-KDD dataset
dataset_path = tk.StringVar()


def make_screen():
    # Create a frame that can be raised to the foreground
    frame = ttk.Frame(root)
    frame.grid(row=0, column=0, sticky="news")
    return frame


# Main Page Design
main_page = make_screen()

# Title
title_label = ttk.Label(
    main_page,
    text="IDS Model Trainer",
    font=("Helvetica", 24, "bold"),
    bootstyle=PRIMARY,
)
title_label.pack(pady=20)

# Description
description_label = ttk.Label(
    main_page,
    text="Welcome to the Intrusion Detection System (IDS) Model Trainer.\n"
    "This tool allows you to train machine learning models for detecting network intrusions.",
    font=("Helvetica", 12),
    bootstyle=INFO,
)
description_label.pack(pady=10)

# Buttons Frame
buttons_frame = ttk.Frame(main_page)
buttons_frame.pack(pady=20)


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


# Load Dataset Button
load_dataset_button = ttk.Button(
    buttons_frame,
    text="Load Dataset",
    command=load_dataset,
    bootstyle=INFO,
    width=20,
    state=DISABLED,
)
load_dataset_button.grid(row=1, column=0, padx=10, pady=10)


def select_dataset():
    path = filedialog.askopenfilename(
        title="Select Dataset",
        initialdir=BASE_DIR,
        filetypes=(("ARFF files", "*.arff"),),
    )
    if path:
        dataset_path.set(path)
        load_dataset_button.config(state=NORMAL)


# Select Dataset Button
select_dataset_button = ttk.Button(
    buttons_frame,
    text="Select Dataset",
    command=select_dataset,
    bootstyle=SUCCESS,
    width=20,
)
select_dataset_button.grid(row=0, column=0, padx=10, pady=10)

# Footer
footer_label = ttk.Label(
    main_page,
    text="© 2025 IDS Model Trainer. All rights reserved.",
    font=("Helvetica", 10),
    bootstyle=SECONDARY,
)
footer_label.pack(side="bottom", pady=10)

load_dataset_frame = ttk.Frame(main_page)
load_dataset_frame.pack()
print_data_graphs = tk.BooleanVar(value=True)
ttk.Checkbutton(
    load_dataset_frame,
    variable=print_data_graphs,
    text="Print data graphs?",
    bootstyle=INFO,
).grid(row=0, column=1)


def train_model():
    print("training")
    print(model_name)
    print(selected_features)
    print(dataset_path.get())
    y_test, y_pred = ml_trainer.train(
        model_name.get(), auto_feature.get(), selected_features, dataset_path.get()
    )
    # call open_model_charts_window() with data from model after training

    open_model_charts_window(y_pred, y_test)


model_name = tk.StringVar(value="Model Algorithm")


def toggle_auto_feature_selection():
    """
    Callback function to toggle visibility of the feature selection UI.
    """
    if not auto_feature.get():  # If auto_feature is False
        feature_label.pack()  # Show the label
        features_frame.pack()  # Show the frame
    else:  # If auto_feature is True
        feature_label.pack_forget()  # Hide the label
        features_frame.pack_forget()  # Hide the frame


select_features_screen = make_screen()
ttk.Button(
    select_features_screen,
    text="Go Back",
    command=lambda: main_page.tkraise(),
    bootstyle=SECONDARY,
).pack(pady=20)
auto_feature = tk.BooleanVar(value=True)
ttk.Checkbutton(
    select_features_screen,
    variable=auto_feature,
    text="auto feature selection",
    bootstyle=INFO,
    command=toggle_auto_feature_selection,
).pack(pady=20)

feature_label = ttk.Label(
    select_features_screen, text="Select the features you want to train with:"
)
features_frame = ttk.Frame(select_features_screen)
features_frame.pack(pady=20, side="right", anchor="se")

feature_label.pack_forget()
features_frame.pack_forget()

train_model_frame = ttk.Frame(select_features_screen)
train_model_frame.pack()

ttk.OptionMenu(
    train_model_frame,
    model_name,
    "Model algorithm",
    *ml_trainer.get_supported_model(),
    bootstyle=INFO,
).pack(side="left", anchor="sw", pady=20, padx=20)
ttk.Button(
    train_model_frame, text="Train Model", command=train_model, bootstyle=SUCCESS
).pack(side="right", anchor="se", pady=20, padx=20)

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

        checkbutton = ttk.Checkbutton(
            features_frame, text=field, variable=var, command=on_check, bootstyle=INFO
        )
        selected_features.append(field)
        checkbutton.grid(
            row=index // grid_columns, column=index % grid_columns, pady=20
        )


def create_scrolled_tab(tab):
    scroll_container = ttk.Frame(tab)
    create_save_close_bar(tab)
    scroll_container.pack(fill="both", expand=True)

    scroll_canvas = tk.Canvas(scroll_container)
    scroll_canvas.pack(side="left", fill="both", expand=True)

    scrollbar = ttk.Scrollbar(
        scroll_container, orient="vertical", command=scroll_canvas.yview
    )
    scrollbar.pack(side="right", fill="y")
    scroll_canvas.configure(yscrollcommand=scrollbar.set)

    plot_frame = ttk.Frame(scroll_canvas)
    scroll_canvas.create_window((0, 0), window=plot_frame, anchor="nw")

    def on_frame_configure(event):
        scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all"))

    plot_frame.bind("<Configure>", on_frame_configure)

    return plot_frame


def get_meter_style(value):
    """
    Returns the meter style (color) based on the value.
    """
    if value < 95:
        return DANGER
    elif 95 <= value <= 97.5:
        return WARNING
    else:
        return SUCCESS


def open_model_charts_window(predictions_mapped, y_test_mapped):
    new_window = ttk.Toplevel(root)
    new_window.title("Model Charts")
    notebook = ttk.Notebook(new_window)
    notebook.pack(fill="both", expand=True)

    # scores
    accuracy = metrics.accuracy_score(y_test_mapped, predictions_mapped)
    sensitivity = metrics.recall_score(y_test_mapped, predictions_mapped, pos_label=1.0)
    precision = metrics.precision_score(
        y_test_mapped, predictions_mapped, pos_label=1.0
    )
    f1_score = metrics.f1_score(y_test_mapped, predictions_mapped, pos_label=1.0)
    recall = metrics.recall_score(y_test_mapped, predictions_mapped, pos_label=1.0)

    tab = ttk.Frame(notebook)
    # Create a top frame for the first row of meters
    top_frame = ttk.Frame(tab)
    top_frame.pack(fill="x", pady=10)

    # Add Accuracy and Sensitivity meters to the top frame
    ttk.Meter(
        top_frame,
        metersize=300,
        amountused=int(accuracy * 100),
        metertype="semi",
        amounttotal=100,
        subtext="Accuracy",
        bootstyle=get_meter_style(int(accuracy * 100)),
        interactive=False,
    ).pack(side="left", padx=20, pady=10, expand=True)

    ttk.Meter(
        top_frame,
        metersize=300,
        amountused=int(sensitivity * 100),
        metertype="semi",
        amounttotal=100,
        subtext="Sensitivity",
        bootstyle=get_meter_style(int(sensitivity * 100)),
        interactive=False,
    ).pack(side="right", padx=20, pady=10, expand=True)

    # Create a middle frame for the second row of meters
    middle_frame = ttk.Frame(tab)
    middle_frame.pack(fill="x", pady=10)

    # Add Precision and F1 Score meters to the middle frame
    ttk.Meter(
        middle_frame,
        metersize=300,
        amountused=int(precision * 100),
        metertype="semi",
        amounttotal=100,
        subtext="Precision",
        bootstyle=get_meter_style(int(precision * 100)),
        interactive=False,
    ).pack(side="left", padx=20, pady=10, expand=True)

    ttk.Meter(
        middle_frame,
        metersize=300,
        amountused=int(f1_score * 100),
        metertype="semi",
        amounttotal=100,
        subtext="F1 Score",
        bootstyle=get_meter_style(int(f1_score * 100)),
        interactive=False,
    ).pack(side="right", padx=20, pady=10, expand=True)

    # Create a bottom frame for the Recall meter
    bottom_frame = ttk.Frame(tab)
    bottom_frame.pack(fill="x", pady=10)

    # Add Recall meter to the bottom frame
    ttk.Meter(
        bottom_frame,
        metersize=300,
        amountused=int(recall * 100),
        metertype="semi",
        amounttotal=100,
        subtext="Recall",
        bootstyle=get_meter_style(int(recall * 100)),
        interactive=False,
    ).pack(pady=10, expand=True)

    # Add the tab to the notebook
    notebook.add(tab, text="Confusion Matrix Stats")

    # confusion matrix
    Confusion_Matrix = metrics.confusion_matrix(y_test_mapped, predictions_mapped)
    disp = ConfusionMatrixDisplay(
        confusion_matrix=Confusion_Matrix, display_labels=["Normal", "Attack"]
    )
    fig, ax = plt.subplots(figsize=(5.5, 5))
    disp.plot(cmap="Blues", ax=ax)

    tab = ttk.Frame(notebook)
    create_tab_with_fig(tab, fig, ax, notebook, "Confusion Matrix")

    # ROC curve
    fpr, tpr, _ = roc_curve(
        [1 if y == 0.0 else 0 for y in y_test_mapped],
        [1 if y == 0.0 else 0 for y in predictions_mapped],
    )
    roc_auc = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(9, 7))
    ax.plot(fpr, tpr, label=f"ROC curve (area = {roc_auc:.2f})", color="blue")
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve")
    ax.legend()

    tab = ttk.Frame(notebook)
    create_tab_with_fig(tab, fig, ax, notebook, "ROC Curve")


def open_data_charts_window():
    new_window = ttk.Toplevel(root)
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
    button_frame = ttk.Frame(diagram_frame)
    button_frame.pack(anchor="n", fill="x")
    button_frame.columnconfigure(0, weight=1)  # Platz zwischen den Buttons
    button_frame.columnconfigure(1, weight=0)
    close_button = ttk.Button(
        button_frame, text="X", bootstyle=DANGER, command=diagram_frame.destroy
    )
    close_button.grid(row=0, column=1, padx=1, sticky="e")
    if fig is None:
        return
    save_button = ttk.Button(
        button_frame, text="Save", bootstyle=INFO, command=lambda: save_fig(fig, title)
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
ttk.Button(
    analysis_screen,
    text="Go Back",
    command=lambda: select_features_screen.tkraise(),
    bootstyle=SECONDARY,
).pack()
fig, ax0 = plt.subplots()
canvas = FigureCanvasTkAgg(figure=fig, master=analysis_screen)
canvas.draw()
canvas.get_tk_widget().pack()

# Start with the main page
main_page.tkraise()
root.mainloop()
