import tkinter as tk

import Base64


def on_label_click(event):
    label = event.widget.cget("text")
    print(f"Clicked label: {label}")


def openNewWindow(e):
    # Clear existing labels in newFrame
    for widget in newFrame.winfo_children():
        widget.destroy()

    labelNew = tk.Label(newFrame, text=e.widget.cget("text"), bg="lightgray", relief="raised")
    labelNew.pack(fill=tk.X)
    labelNew.bind("<Button-1>", showMain)
    label_frame.pack_forget()
    newFrame.pack(fill='both', expand=1)


def showMain(e):
    label_frame.pack(fill='both', expand=1)
    newFrame.pack_forget()


root = tk.Tk()
root.title("Clickable Labels")
root.geometry("500x500")

label_frame = tk.Frame(root)
newFrame = tk.Frame(root)
showMain(None)

# Create clickable labels and pack them on top of each other
labels = ["Label 1", "Label 2", "Label 3", "Label 4", "Label 5"]
for label_text in labels:
    label = tk.Label(label_frame, text=label_text, bg="lightgray", relief="raised", cursor="hand2")
    label.bind("<Button-1>", openNewWindow)
    label.pack(fill=tk.X)

# root.mainloop()

print(Base64.Base64.Decrypt("YWJudmM="))