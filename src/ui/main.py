import tkinter as tk
from tkinter import filedialog, messagebox
import pandas as pd
import scipy.io.arff as arff
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

root = tk.Tk()
root.title('IDS Model Trainer')

# TODO: remove the default value
# TODO: provide option to download NSL-KDD dataset
dataset_path = tk.StringVar(value='/home/justus/Downloads/nsl-kdd/KDDTrain+.arff')

def make_screen():
  # this creates a frame that is always positioned the same,
  # and can be brought to the foreground (switching to the screen)
  # via tkraise()
  frame = tk.Frame(root)
  frame.grid(row=0, column=0, sticky='news')
  return frame

def select_dataset():
  path = filedialog.askopenfilename()
  dataset_path.set(path)

select_dataset_screen = make_screen()
dataset_data = None
dataset_metadata = None
tk.Entry(select_dataset_screen, width=60, textvariable=dataset_path).pack()
tk.Button(select_dataset_screen, text="Select Dataset (ARFF)", command=select_dataset).pack()

def load_dataset():
  global dataset_data, dataset_metadata
  if dataset_path.get().strip() == '':
    messagebox.showerror('Missing Dataset', 'You have not selected a dataset. Please click `Select Dataset`, then continue.')
    return
  try:
    dataset_data, dataset_metadata = arff.loadarff(dataset_path.get())
  except Exception as e:
    messagebox.showerror('Invalid Dataset', f'Dataset is not a valid ARFF file: {e}')
    return
  update_features()
  select_features_screen.tkraise()

tk.Button(select_dataset_screen, text='Load Dataset', command=load_dataset).pack()

def train_model():
  print('training')
  analysis_screen.tkraise()

model_name = tk.StringVar(value='gnb')

select_features_screen = make_screen()
tk.Button(select_features_screen, text='Go Back', command=lambda: select_dataset_screen.tkraise()).pack()
tk.Label(select_features_screen, text='Select the features you want to train with:').pack()
features_frame = tk.Frame(select_features_screen)
features_frame.pack()
tk.OptionMenu(select_features_screen, model_name, 'random_forest', 'gnb', 'cnb').pack()
tk.Button(select_features_screen, text='Train Model', command=train_model).pack()

def update_features():
  # update the list of features
  features_frame.children.clear()
  grid_columns = 4
  for index, field in enumerate(dataset_metadata.names()):
    checkbutton = tk.Checkbutton(features_frame, text=field)
    checkbutton.select()
    checkbutton.grid(row=index // grid_columns, column=index % grid_columns)

analysis_screen = make_screen()
tk.Button(analysis_screen, text='Go Back', command=lambda: select_features_screen.tkraise()).pack()
fig, ax0 = plt.subplots()
canvas = FigureCanvasTkAgg(figure=fig, master=analysis_screen)
canvas.draw()
canvas.get_tk_widget().pack()

select_dataset_screen.tkraise()
root.mainloop()
